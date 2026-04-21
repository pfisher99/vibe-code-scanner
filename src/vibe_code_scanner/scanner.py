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
    FileScanResult,
    RunSummary,
    ScanSourceKind,
    ScanSourceMetadata,
    SourceFile,
)
from .parser import ResponseParseError, normalize_findings, parse_findings
from .prompting import build_messages
from .reporting import (
    initialize_run_dir,
    write_chunk_artifact,
    write_file_artifact,
    write_file_report,
    write_findings_json,
    write_index_markdown,
)

LOGGER = logging.getLogger("vibe_code_scanner")


class RepositoryScanner:
    def __init__(self, config: AppConfig, source_metadata: ScanSourceMetadata | None = None) -> None:
        self._config = config
        self._semaphore = asyncio.Semaphore(config.max_concurrent_requests)
        self._source_metadata = source_metadata or ScanSourceMetadata(
            kind=ScanSourceKind.LOCAL_PATH,
            label=str(config.root_path),
        )

    async def run(self) -> RunSummary:
        started_at = datetime.now(timezone.utc)
        run_id = started_at.astimezone().strftime("%Y%m%d-%H%M%S")
        run_dir = initialize_run_dir(self._config.export_dir, run_id)

        source_files, skipped_paths = discover_source_files(self._config)
        LOGGER.info("Discovered %s files and skipped %s paths.", len(source_files), len(skipped_paths))

        client = OpenAICompatibleClient(self._config)
        tasks = [asyncio.create_task(self._scan_file(run_dir, client, source_file)) for source_file in source_files]
        file_results = await asyncio.gather(*tasks)

        finished_at = datetime.now(timezone.utc)
        summary = self._build_summary(
            run_id=run_id,
            run_dir=run_dir,
            started_at=started_at,
            finished_at=finished_at,
            file_results=file_results,
            skipped_count=len(skipped_paths),
        )

        write_findings_json(run_dir, summary, file_results)
        write_index_markdown(run_dir, summary, file_results)
        LOGGER.info("Finished scan. Results written to %s", run_dir)
        return summary

    async def _scan_file(
        self,
        run_dir: Path,
        client: OpenAICompatibleClient,
        source_file: SourceFile,
    ) -> FileScanResult:
        try:
            LOGGER.info("Scanning %s", source_file.relative_path)
            errors: list[str] = []

            try:
                text = read_text_file(source_file)
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
            all_findings = []

            for chunk in chunks:
                chunk_result = await self._scan_chunk(client, source_file, chunk)
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

    async def _scan_chunk(
        self,
        client: OpenAICompatibleClient,
        source_file: SourceFile,
        chunk,
    ) -> ChunkScanResult:
        messages = build_messages(source_file, chunk, self._config.scan_mode)
        async with self._semaphore:
            try:
                response_text, raw_payload = await client.analyze_messages(messages)
                parsed = parse_findings(response_text)
                findings = normalize_findings(source_file, chunk, parsed)
                return ChunkScanResult(
                    chunk=chunk,
                    findings=findings,
                    raw_response_text=response_text,
                    raw_payload=raw_payload,
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
                    error=error,
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
        )
