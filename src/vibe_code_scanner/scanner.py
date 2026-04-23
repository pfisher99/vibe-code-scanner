"""High-level scan orchestration."""

from __future__ import annotations

import asyncio
import logging
import random
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .chunking import chunk_text
from .client import ModelClientError, OpenAICompatibleClient
from .dedupe import dedupe_findings
from .discovery import discover_source_files, read_text_file
from .models import (
    AppConfig,
    ChunkScanResult,
    ChunkTraceData,
    FileScanResult,
    NormalizedFinding,
    RunSummary,
    ScanMode,
    ScanSourceKind,
    ScanSourceMetadata,
    SkippedPath,
    SourceFile,
)
from .parser import ResponseParseError, normalize_findings, parse_findings
from .prompting import build_messages
from .research import PostScanResearcher
from .reporting import (
    initialize_run_dir,
    write_chunk_artifact,
    write_file_artifact,
    write_file_report,
    write_findings_json,
    write_index_markdown,
    write_research_artifact,
    write_research_report,
)
from .tokenization import TokenizationError
from .tracing import TraceRecorder, append_trace_step

LOGGER = logging.getLogger("vibe_code_scanner")


class RepositoryScanner:
    def __init__(self, config: AppConfig, source_metadata: ScanSourceMetadata | None = None) -> None:
        self._config = config
        self._semaphore = asyncio.Semaphore(config.max_concurrent_requests)
        self._progress_lock = asyncio.Lock()
        self._total_files = 0
        self._completed_files = 0
        self._eligible_files_before_limit = 0
        self._trace_recorder: TraceRecorder | None = None
        self._source_metadata = source_metadata or ScanSourceMetadata(
            kind=ScanSourceKind.LOCAL_PATH,
            label=str(config.root_path),
        )

    async def run(self) -> RunSummary:
        started_at = datetime.now(timezone.utc)
        run_id = started_at.astimezone().strftime("%Y%m%d-%H%M%S")
        run_dir = initialize_run_dir(self._config.export_dir, run_id)
        self._trace_recorder = TraceRecorder(
            run_dir,
            enabled=self._config.trace_enabled,
            logger=LOGGER,
            max_slots=self._config.max_concurrent_requests,
        )
        await self._trace("scan_started", label=self._source_metadata.label, run_id=run_id)

        source_files, skipped_paths = discover_source_files(self._config)
        self._eligible_files_before_limit = len(source_files)
        source_files, skipped_paths = self._apply_max_files_limit(source_files, skipped_paths)
        self._total_files = len(source_files)
        self._completed_files = 0
        LOGGER.debug("Discovered %s files and skipped %s paths.", len(source_files), len(skipped_paths))
        await self._trace(
            "discovery_completed",
            label=self._source_metadata.label,
            file_count=len(source_files),
            skipped_count=len(skipped_paths),
        )

        client = OpenAICompatibleClient(self._config)
        tasks = [asyncio.create_task(self._scan_file(run_dir, client, source_file)) for source_file in source_files]
        file_results = await asyncio.gather(*tasks)
        research_summary = None
        if self._config.research_enabled:
            LOGGER.debug("Running post-scan research loop.")
            await self._trace("research_started", label=self._source_metadata.label)
            research_summary = await PostScanResearcher(self._config).run(
                client,
                file_results,
                self._source_metadata,
                trace_recorder=self._trace_recorder,
            )
            research_summary.raw_artifact_path = write_research_artifact(run_dir, research_summary)
            research_summary.report_path = write_research_report(run_dir, research_summary)

        finished_at = datetime.now(timezone.utc)
        summary = self._build_summary(
            run_id=run_id,
            run_dir=run_dir,
            started_at=started_at,
            finished_at=finished_at,
            file_results=file_results,
            skipped_count=len(skipped_paths),
            research_summary=research_summary,
        )

        write_findings_json(run_dir, summary, file_results, research_summary=research_summary)
        write_index_markdown(run_dir, summary, file_results, research_summary=research_summary)
        await self._trace(
            "scan_finished",
            label=self._source_metadata.label,
            status="ok",
            scanned_files=summary.total_files_scanned,
            total_chunks=summary.total_chunks_sent,
            error_count=len(summary.errors),
        )
        LOGGER.info("Finished scan. Results written to %s", run_dir)
        return summary

    async def _scan_file(
        self,
        run_dir: Path,
        client: OpenAICompatibleClient,
        source_file: SourceFile,
    ) -> FileScanResult:
        line_count = 0
        try:
            LOGGER.debug("Scanning %s", source_file.relative_path)
            await self._trace("file_started", label=source_file.relative_path, file_path=source_file.relative_path)
            errors: list[str] = []

            try:
                text = read_text_file(source_file)
                line_count = len(text.splitlines())
            except OSError as exc:
                error = f"{source_file.relative_path}: failed to read file ({exc})"
                LOGGER.error(error)
                await self._trace(
                    "file_failed",
                    label=source_file.relative_path,
                    file_path=source_file.relative_path,
                    error=str(exc),
                )
                errors.append(error)
                file_result = FileScanResult(
                    source_file=source_file,
                    report_path=None,
                    raw_artifact_path=None,
                    chunks_scanned=0,
                    findings=[],
                    errors=errors,
                )
                raw_artifact_path = write_file_artifact(run_dir, file_result)
                file_result.raw_artifact_path = raw_artifact_path
                file_result.report_path = write_file_report(run_dir, file_result)
                return file_result

            try:
                chunks = await asyncio.to_thread(chunk_text, text, self._config)
            except TokenizationError as exc:
                error = f"{source_file.relative_path}: failed to size chunks with the configured tokenizer ({exc})"
                LOGGER.error(error)
                await self._trace(
                    "file_chunking_failed",
                    label=source_file.relative_path,
                    file_path=source_file.relative_path,
                    error=str(exc),
                )
                errors.append(error)
                file_result = FileScanResult(
                    source_file=source_file,
                    report_path=None,
                    raw_artifact_path=None,
                    chunks_scanned=0,
                    findings=[],
                    errors=errors,
                )
                file_result.raw_artifact_path = write_file_artifact(run_dir, file_result)
                file_result.report_path = write_file_report(run_dir, file_result)
                return file_result
            await self._trace(
                "file_chunked",
                label=source_file.relative_path,
                file_path=source_file.relative_path,
                total_chunks=len(chunks),
                line_count=line_count,
            )
            chunk_tasks = [
                asyncio.create_task(self._scan_chunk(client, source_file, chunk))
                for chunk in chunks
            ]
            chunk_results = await asyncio.gather(*chunk_tasks) if chunk_tasks else []
            all_findings = []

            for chunk_result in chunk_results:
                write_chunk_artifact(run_dir, source_file.relative_path, chunk_result)
                all_findings.extend(chunk_result.findings)
                if chunk_result.error:
                    errors.append(chunk_result.error)

            deduped_findings = dedupe_findings(all_findings)
            file_result = FileScanResult(
                source_file=source_file,
                report_path=None,
                raw_artifact_path=None,
                chunks_scanned=len(chunks),
                findings=deduped_findings,
                errors=errors,
            )
            file_result.raw_artifact_path = write_file_artifact(run_dir, file_result)
            file_result.report_path = write_file_report(run_dir, file_result)
            await self._trace(
                "file_completed",
                label=source_file.relative_path,
                file_path=source_file.relative_path,
                finding_count=len(deduped_findings),
                error_count=len(errors),
            )
            return file_result
        except Exception as exc:
            error = f"{source_file.relative_path}: unexpected scan failure ({exc})"
            LOGGER.exception(error)
            await self._trace(
                "file_failed",
                label=source_file.relative_path,
                file_path=source_file.relative_path,
                error=str(exc),
            )
            file_result = FileScanResult(
                source_file=source_file,
                report_path=None,
                raw_artifact_path=None,
                chunks_scanned=0,
                findings=[],
                errors=[error],
            )
            file_result.raw_artifact_path = write_file_artifact(run_dir, file_result)
            file_result.report_path = write_file_report(run_dir, file_result)
            return file_result
        finally:
            await self._log_file_progress(source_file.relative_path, line_count)

    async def _scan_chunk(
        self,
        client: OpenAICompatibleClient,
        source_file: SourceFile,
        chunk,
    ) -> ChunkScanResult:
        messages = build_messages(source_file, chunk, self._config.scan_mode)
        trace_label = f"{source_file.relative_path} chunk {chunk.chunk_index}/{chunk.total_chunks}"
        await self._trace(
            "chunk_queued",
            label=trace_label,
            file_path=source_file.relative_path,
            chunk_index=chunk.chunk_index,
            total_chunks=chunk.total_chunks,
            line_start=chunk.start_line,
            line_end=chunk.end_line,
            estimated_tokens=chunk.estimated_tokens,
        )
        async with self._semaphore:
            slot_id = await self._acquire_trace_slot(trace_label)
            try:
                await self._trace(
                    "chunk_request_started",
                    label=trace_label,
                    slot_id=slot_id,
                    file_path=source_file.relative_path,
                    chunk_index=chunk.chunk_index,
                    total_chunks=chunk.total_chunks,
                )
                response_text, raw_payload, trace_data = await client.analyze_messages(
                    messages,
                    trace_label=trace_label,
                    slot_id=slot_id,
                )
                if trace_data is not None:
                    append_trace_step(
                        trace_data,
                        "parse_started",
                        chunk_index=chunk.chunk_index,
                        total_chunks=chunk.total_chunks,
                    )
                parsed = parse_findings(response_text)
                findings = normalize_findings(source_file, chunk, parsed)
                findings = _filter_findings_for_mode(findings, self._config.scan_mode)
                if trace_data is not None:
                    append_trace_step(
                        trace_data,
                        "parse_succeeded",
                        finding_count=len(findings),
                    )
                await self._trace(
                    "chunk_request_completed",
                    label=trace_label,
                    slot_id=slot_id,
                    file_path=source_file.relative_path,
                    chunk_index=chunk.chunk_index,
                    total_chunks=chunk.total_chunks,
                    finding_count=len(findings),
                    duration_ms=(trace_data.duration_ms if trace_data is not None else None),
                )
                return ChunkScanResult(
                    chunk=chunk,
                    findings=findings,
                    raw_response_text=response_text,
                    raw_payload=raw_payload,
                    trace=trace_data,
                    error=None,
                )
            except (ModelClientError, ResponseParseError) as exc:
                error = (
                    f"{source_file.relative_path} chunk {chunk.chunk_index}/{chunk.total_chunks}: {exc}"
                )
                LOGGER.warning(error)
                failed_trace = (
                    exc.trace_data
                    if isinstance(exc, ModelClientError) and exc.trace_data is not None
                    else _build_failed_trace(messages, self._config, trace_label=trace_label, slot_id=slot_id)
                )
                append_trace_step(failed_trace, "chunk_failed", error=str(exc))
                await self._trace(
                    "chunk_request_failed",
                    label=trace_label,
                    slot_id=slot_id,
                    file_path=source_file.relative_path,
                    chunk_index=chunk.chunk_index,
                    total_chunks=chunk.total_chunks,
                    error=str(exc),
                )
                return ChunkScanResult(
                    chunk=chunk,
                    findings=[],
                    raw_response_text=(response_text if "response_text" in locals() else None),
                    raw_payload=None,
                    trace=failed_trace,
                    error=error,
                )
            except Exception as exc:
                error = (
                    f"{source_file.relative_path} chunk {chunk.chunk_index}/{chunk.total_chunks}: "
                    f"unexpected failure ({exc})"
                )
                LOGGER.exception(error)
                failed_trace = _build_failed_trace(messages, self._config, trace_label=trace_label, slot_id=slot_id)
                append_trace_step(failed_trace, "chunk_failed", error=str(exc))
                await self._trace(
                    "chunk_request_failed",
                    label=trace_label,
                    slot_id=slot_id,
                    file_path=source_file.relative_path,
                    chunk_index=chunk.chunk_index,
                    total_chunks=chunk.total_chunks,
                    error=str(exc),
                )
                return ChunkScanResult(
                    chunk=chunk,
                    findings=[],
                    raw_response_text=None,
                    raw_payload=None,
                    trace=failed_trace,
                    error=error,
                )
            finally:
                await self._release_trace_slot(slot_id, trace_label)

    async def _log_file_progress(self, relative_path: str, line_count: int) -> None:
        if self._total_files <= 0:
            return
        async with self._progress_lock:
            self._completed_files += 1
            remaining_files = max(0, self._total_files - self._completed_files)
            percent_remaining = (remaining_files / self._total_files) * 100
            LOGGER.info(
                "Completed %s: %s lines scanned. %s/%s files remaining (%.1f%% remaining).",
                relative_path,
                line_count,
                remaining_files,
                self._total_files,
                percent_remaining,
            )

    def _build_summary(
        self,
        *,
        run_id: str,
        run_dir: Path,
        started_at: datetime,
        finished_at: datetime,
        file_results: list[FileScanResult],
        skipped_count: int,
        research_summary=None,
    ) -> RunSummary:
        severity_counts = Counter()
        file_counts: list[tuple[str, int]] = []
        errors: list[str] = []
        total_chunks = 0

        for result in file_results:
            total_chunks += result.chunks_scanned
            file_counts.append((result.source_file.relative_path, len(result.findings)))
            for finding in result.findings:
                severity_counts[finding.severity.value] += 1
            errors.extend(result.errors)
        if research_summary is not None:
            errors.extend(research_summary.errors)

        top_files = [item for item in sorted(file_counts, key=lambda item: item[1], reverse=True) if item[1] > 0][:10]
        return RunSummary(
            run_id=run_id,
            run_dir=run_dir,
            started_at=started_at,
            finished_at=finished_at,
            source_kind=self._source_metadata.kind.value,
            source_label=self._source_metadata.label,
            source_repo_url=self._source_metadata.repo_url,
            requested_ref=self._source_metadata.requested_ref,
            checked_out_ref=self._source_metadata.checked_out_ref,
            root_path=self._config.root_path,
            base_url=self._config.base_url,
            model_name=self._config.model_name,
            api_style=self._config.api_style.value,
            scan_mode=self._config.scan_mode.value,
            total_files_scanned=len(file_results),
            total_files_skipped=skipped_count,
            total_chunks_sent=total_chunks,
            findings_by_severity=dict(severity_counts),
            top_files=top_files,
            errors=errors,
            research_enabled=self._config.research_enabled,
            trace_enabled=self._config.trace_enabled,
            research_tool_calls=(len(research_summary.tool_calls) if research_summary is not None else 0),
            research_search_queries=(len(research_summary.search_queries) if research_summary is not None else 0),
            research_references_collected=(
                len(research_summary.references) if research_summary is not None else 0
            ),
            max_files_limit=self._config.max_files,
            eligible_files_before_limit=(
                self._eligible_files_before_limit if self._config.max_files is not None else None
            ),
        )

    def _apply_max_files_limit(
        self,
        source_files: list[SourceFile],
        skipped_paths: list[SkippedPath],
    ) -> tuple[list[SourceFile], list[SkippedPath]]:
        max_files = self._config.max_files
        if max_files is None or len(source_files) <= max_files:
            return source_files, skipped_paths

        selected_files = random.sample(source_files, max_files)
        selected_relative_paths = {source_file.relative_path for source_file in selected_files}
        limited_source_files = sorted(selected_files, key=lambda item: item.relative_path)
        omitted_files = [
            source_file for source_file in source_files if source_file.relative_path not in selected_relative_paths
        ]
        limited_skips = list(skipped_paths)
        limited_skips.extend(
            SkippedPath(relative_path=source_file.relative_path, reason="max_files_limit")
            for source_file in omitted_files
        )
        limited_skips.sort(key=lambda item: item.relative_path)
        LOGGER.debug(
            "Limiting scan to a random subset of %s file(s) out of %s eligible files.",
            len(limited_source_files),
            len(source_files),
        )
        return limited_source_files, limited_skips

    async def _trace(self, event: str, **details) -> None:
        if self._trace_recorder is None:
            return
        await self._trace_recorder.record(event, **details)

    async def _acquire_trace_slot(self, label: str) -> int | None:
        if self._trace_recorder is None:
            return None
        return await self._trace_recorder.acquire_slot(label)

    async def _release_trace_slot(self, slot_id: int | None, label: str) -> None:
        if self._trace_recorder is None:
            return
        await self._trace_recorder.release_slot(slot_id, label)


def _build_failed_trace(
    messages: list[dict[str, str]],
    config: AppConfig,
    *,
    trace_label: str | None = None,
    slot_id: int | None = None,
) -> ChunkTraceData | None:
    if not config.trace_enabled:
        return None
    return ChunkTraceData(
        request_messages=[dict(message) for message in messages],
        trace_label=trace_label,
        slot_id=slot_id,
        request_message_count=len(messages),
        request_char_count=sum(len(str(message.get("content", ""))) for message in messages),
    )


def _filter_findings_for_mode(
    findings: list[NormalizedFinding],
    scan_mode: ScanMode,
) -> list[NormalizedFinding]:
    if scan_mode != ScanMode.HIGH_SECURITY:
        return findings
    return [
        finding
        for finding in findings
        if finding.category.value == "security" and finding.severity.value in {"critical", "high"}
    ]
