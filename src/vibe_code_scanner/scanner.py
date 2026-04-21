"""High-level scan orchestration."""

from __future__ import annotations

import asyncio
import logging
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
    RunSummary,
    ScanSourceKind,
    ScanSourceMetadata,
    SourceFile,
)
from .parser import ResponseParseError, normalize_findings, parse_findings
from .prompting import build_messages
from .research import DependencyResearcher
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
from .tracing import LiveTracePrinter

LOGGER = logging.getLogger("vibe_code_scanner")


class RepositoryScanner:
    def __init__(self, config: AppConfig, source_metadata: ScanSourceMetadata | None = None) -> None:
        self._config = config
        self._semaphore = asyncio.Semaphore(config.max_concurrent_requests)
        self._progress_lock = asyncio.Lock()
        self._total_files = 0
        self._completed_files = 0
        self._live_trace_printer = LiveTracePrinter() if config.trace_live_enabled else None
        self._source_metadata = source_metadata or ScanSourceMetadata(
            kind=ScanSourceKind.LOCAL_PATH,
            label=str(config.root_path),
        )

    async def run(self) -> RunSummary:
        started_at = datetime.now(timezone.utc)
        run_id = started_at.astimezone().strftime("%Y%m%d-%H%M%S")
        run_dir = initialize_run_dir(self._config.export_dir, run_id)

        source_files, skipped_paths = discover_source_files(self._config)
        self._total_files = len(source_files)
        self._completed_files = 0
        LOGGER.info("Discovered %s files and skipped %s paths.", len(source_files), len(skipped_paths))

        client = OpenAICompatibleClient(self._config)
        tasks = [asyncio.create_task(self._scan_file(run_dir, client, source_file)) for source_file in source_files]
        file_results = await asyncio.gather(*tasks)
        research_summary = None
        if self._config.research_enabled:
            LOGGER.info("Running dependency research enrichment.")
            research_summary = await asyncio.to_thread(DependencyResearcher(self._config).run, source_files)
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
            LOGGER.info("Scanning %s", source_file.relative_path)
            errors: list[str] = []

            try:
                text = read_text_file(source_file)
                line_count = len(text.splitlines())
            except OSError as exc:
                error = f"{source_file.relative_path}: failed to read file ({exc})"
                LOGGER.error(error)
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

            chunks = chunk_text(text, self._config)
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
            return file_result
        except Exception as exc:
            error = f"{source_file.relative_path}: unexpected scan failure ({exc})"
            LOGGER.exception(error)
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
        async with self._semaphore:
            try:
                response_text, raw_payload, trace_data = await client.analyze_messages(
                    messages,
                    trace_label=trace_label,
                    live_trace_printer=self._live_trace_printer,
                )
                parsed = parse_findings(response_text)
                findings = normalize_findings(source_file, chunk, parsed)
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
                return ChunkScanResult(
                    chunk=chunk,
                    findings=[],
                    raw_response_text=None,
                    raw_payload=None,
                    trace=_build_failed_trace(messages, self._config),
                    error=error,
                )
            except Exception as exc:
                error = (
                    f"{source_file.relative_path} chunk {chunk.chunk_index}/{chunk.total_chunks}: "
                    f"unexpected failure ({exc})"
                )
                LOGGER.exception(error)
                return ChunkScanResult(
                    chunk=chunk,
                    findings=[],
                    raw_response_text=None,
                    raw_payload=None,
                    trace=_build_failed_trace(messages, self._config),
                    error=error,
                )

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
            total_dependencies_researched=(
                research_summary.total_dependencies if research_summary is not None else 0
            ),
            vulnerable_dependencies=(
                research_summary.vulnerable_dependencies if research_summary is not None else 0
            ),
            searched_dependencies=(
                research_summary.searched_dependencies if research_summary is not None else 0
            ),
        )


def _build_failed_trace(messages: list[dict[str, str]], config: AppConfig) -> ChunkTraceData | None:
    if not config.trace_enabled:
        return None
    return ChunkTraceData(
        request_messages=[dict(message) for message in messages],
        used_streaming=False,
        live_streaming_requested=config.trace_live_enabled,
    )
