"""Run artifact and markdown report generation."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from .defaults import CATEGORY_DISPLAY_NAMES, SEVERITY_ORDER
from .models import (
    ChunkScanResult,
    DependencyResearchItem,
    FileScanResult,
    NormalizedFinding,
    ResearchSummary,
    RunSummary,
)


def initialize_run_dir(export_dir: Path, run_id: str) -> Path:
    run_dir = export_dir / run_id
    (run_dir / "files").mkdir(parents=True, exist_ok=True)
    (run_dir / "research").mkdir(parents=True, exist_ok=True)
    (run_dir / "raw" / "chunks").mkdir(parents=True, exist_ok=True)
    (run_dir / "raw" / "files").mkdir(parents=True, exist_ok=True)
    (run_dir / "raw" / "research").mkdir(parents=True, exist_ok=True)
    return run_dir


def write_chunk_artifact(run_dir: Path, file_path: str, result: ChunkScanResult) -> Path:
    artifact_path = _chunk_artifact_path(run_dir, file_path, result.chunk.chunk_index)
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "file_path": file_path,
        "chunk_index": result.chunk.chunk_index,
        "total_chunks": result.chunk.total_chunks,
        "line_start": result.chunk.start_line,
        "line_end": result.chunk.end_line,
        "estimated_tokens": result.chunk.estimated_tokens,
        "overlap_from_previous_tokens": result.chunk.overlap_from_previous_tokens,
        "overlap_from_previous_lines": result.chunk.overlap_from_previous_lines,
        "error": result.error,
        "raw_response_text": result.raw_response_text,
        "raw_payload": result.raw_payload,
        "trace": _trace_to_dict(result.trace),
        "findings": [_finding_to_dict(finding) for finding in result.findings],
    }
    artifact_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return artifact_path


def write_file_artifact(run_dir: Path, file_result: FileScanResult) -> Path:
    artifact_path = _file_artifact_path(run_dir, file_result.source_file.relative_path)
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "file_path": file_result.source_file.relative_path,
        "chunks_scanned": file_result.chunks_scanned,
        "findings": [_finding_to_dict(finding) for finding in file_result.findings],
        "errors": file_result.errors,
    }
    artifact_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return artifact_path


def write_file_report(run_dir: Path, file_result: FileScanResult) -> Path:
    report_path = _file_report_path(run_dir, file_result.source_file.relative_path)
    report_path.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        f"# {file_result.source_file.relative_path}",
        "",
        "## Scan Metadata",
        "",
        f"- File path: `{file_result.source_file.relative_path}`",
        f"- File size: `{file_result.source_file.size_bytes}` bytes",
        f"- Chunks scanned: `{file_result.chunks_scanned}`",
        f"- Findings: `{len(file_result.findings)}`",
    ]

    if file_result.errors:
        lines.extend(["", "## Errors", ""])
        lines.extend(f"- {error}" for error in file_result.errors)

    grouped = _group_findings_by_severity(file_result.findings)
    lines.extend(["", "## Findings", ""])

    if not file_result.findings:
        lines.append("No findings reported for this file.")
    else:
        for severity in SEVERITY_ORDER:
            findings = grouped.get(severity, [])
            if not findings:
                continue
            lines.extend(["", f"### {severity.title()} ({len(findings)})", ""])
            for index, finding in enumerate(findings, start=1):
                lines.append(f"#### {index}. {finding.title}")
                lines.append("")
                lines.append(f"- Category: {CATEGORY_DISPLAY_NAMES[finding.category.value]}")
                lines.append(f"- Severity: `{finding.severity.value}`")
                lines.append(f"- Confidence: `{finding.confidence.value}`")
                lines.append(f"- Chunks: `{', '.join(str(chunk_id) for chunk_id in finding.chunk_ids)}`")
                lines.append(f"- Lines: `{_format_line_range(finding)}`")
                lines.append(f"- Explanation: {finding.explanation or 'No explanation provided.'}")
                lines.append(f"- Evidence: {finding.evidence or 'No evidence provided.'}")
                lines.append(f"- Remediation: {finding.remediation or 'No remediation provided.'}")
                lines.append("")

    report_path.write_text("\n".join(lines).strip() + "\n", encoding="utf-8")
    return report_path


def write_findings_json(
    run_dir: Path,
    summary: RunSummary,
    file_results: list[FileScanResult],
    research_summary: ResearchSummary | None = None,
) -> Path:
    path = run_dir / "findings.json"
    payload = {
        "run_summary": _summary_to_dict(summary),
        "research_summary": _research_summary_to_dict(research_summary),
        "files": [
            {
                "file_path": result.source_file.relative_path,
                "chunks_scanned": result.chunks_scanned,
                "findings": [_finding_to_dict(finding) for finding in result.findings],
                "errors": result.errors,
            }
            for result in file_results
        ],
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def write_research_artifact(run_dir: Path, research_summary: ResearchSummary) -> Path:
    path = run_dir / "raw" / "research" / "dependencies.json"
    payload = {
        "total_dependencies": research_summary.total_dependencies,
        "vulnerable_dependencies": research_summary.vulnerable_dependencies,
        "searched_dependencies": research_summary.searched_dependencies,
        "errors": research_summary.errors,
        "dependencies": [_dependency_to_dict(item) for item in research_summary.dependencies],
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def write_research_report(run_dir: Path, research_summary: ResearchSummary) -> Path:
    path = run_dir / "research" / "dependencies.md"
    lines = [
        "# Dependency Research",
        "",
        f"- Total dependencies researched: `{research_summary.total_dependencies}`",
        f"- Vulnerable dependencies: `{research_summary.vulnerable_dependencies}`",
        f"- Dependencies with search results: `{research_summary.searched_dependencies}`",
    ]

    if research_summary.errors:
        lines.extend(["", "## Errors", ""])
        lines.extend(f"- {error}" for error in research_summary.errors)

    lines.extend(["", "## Dependencies", ""])
    if not research_summary.dependencies:
        lines.append("No dependency manifests were parsed for research.")
    else:
        for dependency in research_summary.dependencies:
            lines.extend(
                [
                    "",
                    f"### {dependency.name}",
                    "",
                    f"- Source file: `{dependency.source_file}`",
                    f"- Ecosystem: `{dependency.ecosystem}`",
                    f"- Declared version: `{dependency.version_spec or 'unversioned'}`",
                    f"- Exact version used for vulnerability lookup: `{dependency.resolved_version or 'not exact / unavailable'}`",
                    f"- Latest known version: `{dependency.latest_version or 'unknown'}`",
                    f"- Vulnerabilities: `{len(dependency.vulnerabilities)}`",
                ]
            )
            if dependency.errors:
                lines.extend(f"- Research error: {error}" for error in dependency.errors)
            if dependency.vulnerabilities:
                lines.extend(["", "#### Known Vulnerabilities", ""])
                for vulnerability in dependency.vulnerabilities:
                    lines.append(f"- `{vulnerability.id}`: {vulnerability.summary or 'No summary provided.'}")
                    if vulnerability.severity:
                        lines.append(f"  Severity: `{vulnerability.severity}`")
                    if vulnerability.references:
                        for reference in vulnerability.references:
                            lines.append(f"  Reference: [{reference.title}]({reference.url})")
            if dependency.search_results:
                lines.extend(["", "#### Search Results", ""])
                for result in dependency.search_results:
                    lines.append(f"- [{result.title}]({result.url}): {result.snippet or 'No snippet provided.'}")

    path.write_text("\n".join(lines).strip() + "\n", encoding="utf-8")
    return path


def write_index_markdown(
    run_dir: Path,
    summary: RunSummary,
    file_results: list[FileScanResult],
    research_summary: ResearchSummary | None = None,
) -> Path:
    path = run_dir / "index.md"
    lines = [
        "# Scan Summary",
        "",
        "## Overview",
        "",
        f"- Scan source type: `{summary.source_kind}`",
        f"- Scan source: `{summary.source_label}`",
    ]

    if summary.source_repo_url:
        lines.append(f"- Source repo URL: `{summary.source_repo_url}`")
    if summary.requested_ref:
        lines.append(f"- Requested ref: `{summary.requested_ref}`")
    if summary.checked_out_ref:
        lines.append(f"- Checked out ref: `{summary.checked_out_ref}`")

    lines.extend(
        [
        f"- Scan root: `{summary.root_path}`",
        f"- Model endpoint: `{summary.base_url}`",
        f"- Model name: `{summary.model_name}`",
        f"- API style: `{summary.api_style}`",
        f"- Scan mode: `{summary.scan_mode}`",
        f"- Started: `{summary.started_at.isoformat()}`",
        f"- Finished: `{summary.finished_at.isoformat()}`",
        f"- Total files scanned: `{summary.total_files_scanned}`",
        f"- Total files skipped: `{summary.total_files_skipped}`",
        f"- Total chunks sent: `{summary.total_chunks_sent}`",
        f"- Research enabled: `{summary.research_enabled}`",
        "",
        "## Findings By Severity",
        "",
        ]
    )

    if summary.research_enabled:
        lines.extend(
            [
                "",
                "## Dependency Research",
                "",
                f"- Dependencies researched: `{summary.total_dependencies_researched}`",
                f"- Vulnerable dependencies: `{summary.vulnerable_dependencies}`",
                f"- Dependencies with search results: `{summary.searched_dependencies}`",
            ]
        )
        if research_summary and research_summary.report_path is not None:
            report_link = research_summary.report_path.relative_to(run_dir).as_posix()
            lines.append(f"- Report: [{report_link}]({report_link})")

    for severity in SEVERITY_ORDER:
        lines.append(f"- {severity}: `{summary.findings_by_severity.get(severity, 0)}`")

    lines.extend(["", "## Top Files", ""])
    if summary.top_files:
        for file_path, count in summary.top_files:
            report_link = _file_report_path(run_dir, file_path).relative_to(run_dir).as_posix()
            lines.append(f"- [{file_path}]({report_link}): `{count}` findings")
    else:
        lines.append("- No findings reported.")

    lines.extend(["", "## Files", ""])
    for result in file_results:
        report_link = (
            result.report_path.relative_to(run_dir).as_posix()
            if result.report_path is not None
            else None
        )
        label = result.source_file.relative_path
        if report_link:
            lines.append(f"- [{label}]({report_link}): `{len(result.findings)}` findings")
        else:
            lines.append(f"- {label}: report not generated")

    lines.extend(["", "## Errors", ""])
    if summary.errors:
        lines.extend(f"- {error}" for error in summary.errors)
    else:
        lines.append("- No errors encountered.")

    path.write_text("\n".join(lines).strip() + "\n", encoding="utf-8")
    return path


def _file_report_path(run_dir: Path, relative_path: str) -> Path:
    target = run_dir / "files" / Path(relative_path)
    return target.with_name(target.name + ".md")


def _chunk_artifact_path(run_dir: Path, relative_path: str, chunk_index: int) -> Path:
    target = run_dir / "raw" / "chunks" / Path(relative_path)
    return target.with_name(f"{target.name}.chunk-{chunk_index:04d}.json")


def _file_artifact_path(run_dir: Path, relative_path: str) -> Path:
    target = run_dir / "raw" / "files" / Path(relative_path)
    return target.with_name(f"{target.name}.json")


def _group_findings_by_severity(findings: list[NormalizedFinding]) -> dict[str, list[NormalizedFinding]]:
    grouped: dict[str, list[NormalizedFinding]] = {}
    for finding in findings:
        grouped.setdefault(finding.severity.value, []).append(finding)
    return grouped


def _format_line_range(finding: NormalizedFinding) -> str:
    if finding.line_start is None and finding.line_end is None:
        return "unknown"
    if finding.line_start == finding.line_end or finding.line_end is None:
        return str(finding.line_start)
    if finding.line_start is None:
        return str(finding.line_end)
    return f"{finding.line_start}-{finding.line_end}"


def _finding_to_dict(finding: NormalizedFinding) -> dict:
    payload = asdict(finding)
    payload["category"] = finding.category.value
    payload["severity"] = finding.severity.value
    payload["confidence"] = finding.confidence.value
    return payload


def _summary_to_dict(summary: RunSummary) -> dict:
    payload = asdict(summary)
    payload["started_at"] = summary.started_at.isoformat()
    payload["finished_at"] = summary.finished_at.isoformat()
    payload["root_path"] = str(summary.root_path)
    payload["run_dir"] = str(summary.run_dir)
    return payload


def _trace_to_dict(trace) -> dict | None:
    if trace is None:
        return None
    return {
        "request_messages": trace.request_messages,
        "used_streaming": trace.used_streaming,
        "live_streaming_requested": trace.live_streaming_requested,
        "stream_fallback_reason": trace.stream_fallback_reason,
    }


def _dependency_to_dict(dependency: DependencyResearchItem) -> dict:
    return {
        "source_file": dependency.source_file,
        "ecosystem": dependency.ecosystem,
        "name": dependency.name,
        "version_spec": dependency.version_spec,
        "resolved_version": dependency.resolved_version,
        "latest_version": dependency.latest_version,
        "vulnerabilities": [
            {
                "id": vulnerability.id,
                "summary": vulnerability.summary,
                "aliases": vulnerability.aliases,
                "severity": vulnerability.severity,
                "references": [
                    {"title": reference.title, "url": reference.url, "snippet": reference.snippet}
                    for reference in vulnerability.references
                ],
            }
            for vulnerability in dependency.vulnerabilities
        ],
        "search_results": [
            {"title": reference.title, "url": reference.url, "snippet": reference.snippet}
            for reference in dependency.search_results
        ],
        "errors": dependency.errors,
    }


def _research_summary_to_dict(summary: ResearchSummary | None) -> dict | None:
    if summary is None:
        return None
    return {
        "total_dependencies": summary.total_dependencies,
        "vulnerable_dependencies": summary.vulnerable_dependencies,
        "searched_dependencies": summary.searched_dependencies,
        "errors": summary.errors,
        "report_path": str(summary.report_path) if summary.report_path else None,
        "raw_artifact_path": str(summary.raw_artifact_path) if summary.raw_artifact_path else None,
        "dependencies": [_dependency_to_dict(item) for item in summary.dependencies],
    }
