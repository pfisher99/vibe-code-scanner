"""Typed data models used across the scanner."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from pathlib import Path


class ScanMode(StrEnum):
    SECURITY = "security"
    SECURITY_AND_QUALITY = "security_and_quality"


class ApiStyle(StrEnum):
    CHAT_COMPLETIONS = "chat_completions"
    RESPONSES = "responses"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Category(StrEnum):
    SECURITY = "security"
    CORRECTNESS = "correctness"
    MAINTAINABILITY = "maintainability"
    SUSPICIOUS_PATTERN = "suspicious_pattern"
    STYLE_PREFERENCE = "style_preference"


class ScanSourceKind(StrEnum):
    LOCAL_PATH = "local_path"
    GITHUB_REPO = "github_repo"


class SearchBackend(StrEnum):
    NONE = "none"
    SEARXNG = "searxng"


@dataclass(slots=True)
class AppConfig:
    root_path: Path
    export_dir: Path
    base_url: str
    model_name: str
    api_style: ApiStyle
    scan_mode: ScanMode
    max_concurrent_requests: int
    max_tokens_per_request: int
    chunk_target_tokens: int
    chunk_overlap_tokens: int
    request_timeout_seconds: float
    retry_count: int
    max_file_size_bytes: int
    include_globs: list[str] = field(default_factory=list)
    exclude_globs: list[str] = field(default_factory=list)
    ignored_directories: list[str] = field(default_factory=list)
    api_key: str | None = None
    trace_enabled: bool = False
    trace_live_enabled: bool = False
    research_enabled: bool = False
    search_backend: SearchBackend = SearchBackend.NONE
    search_base_url: str | None = None
    research_max_results: int = 3


@dataclass(slots=True)
class ScanSourceMetadata:
    kind: ScanSourceKind
    label: str
    repo_url: str | None = None
    requested_ref: str | None = None
    checked_out_ref: str | None = None


@dataclass(slots=True)
class SourceFile:
    root_path: Path
    path: Path
    relative_path: str
    size_bytes: int
    language_hint: str


@dataclass(slots=True)
class SkippedPath:
    relative_path: str
    reason: str


@dataclass(slots=True)
class CodeChunk:
    chunk_index: int
    total_chunks: int
    start_line: int
    end_line: int
    text: str
    estimated_tokens: int
    overlap_from_previous_tokens: int
    overlap_from_previous_lines: int


@dataclass(slots=True)
class ParsedFinding:
    title: str
    category: Category
    severity: Severity
    confidence: Confidence
    line_start: int | None
    line_end: int | None
    explanation: str
    evidence: str
    remediation: str


@dataclass(slots=True)
class NormalizedFinding:
    file_path: str
    chunk_ids: list[int]
    title: str
    category: Category
    severity: Severity
    confidence: Confidence
    line_start: int | None
    line_end: int | None
    explanation: str
    evidence: str
    remediation: str


@dataclass(slots=True)
class ChunkTraceData:
    request_messages: list[dict[str, str]] | None
    used_streaming: bool
    live_streaming_requested: bool
    stream_fallback_reason: str | None = None


@dataclass(slots=True)
class ResearchReference:
    title: str
    url: str
    snippet: str = ""


@dataclass(slots=True)
class DependencyVulnerability:
    id: str
    summary: str
    aliases: list[str] = field(default_factory=list)
    severity: str | None = None
    references: list[ResearchReference] = field(default_factory=list)


@dataclass(slots=True)
class DependencyResearchItem:
    source_file: str
    ecosystem: str
    name: str
    version_spec: str | None
    resolved_version: str | None
    latest_version: str | None
    vulnerabilities: list[DependencyVulnerability] = field(default_factory=list)
    search_results: list[ResearchReference] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ResearchSummary:
    dependencies: list[DependencyResearchItem] = field(default_factory=list)
    total_dependencies: int = 0
    vulnerable_dependencies: int = 0
    searched_dependencies: int = 0
    errors: list[str] = field(default_factory=list)
    report_path: Path | None = None
    raw_artifact_path: Path | None = None


@dataclass(slots=True)
class ChunkScanResult:
    chunk: CodeChunk
    findings: list[NormalizedFinding]
    raw_response_text: str | None
    raw_payload: dict | None
    trace: ChunkTraceData | None = None
    error: str | None = None


@dataclass(slots=True)
class FileScanResult:
    source_file: SourceFile
    report_path: Path | None
    raw_artifact_path: Path | None
    chunks_scanned: int
    findings: list[NormalizedFinding]
    errors: list[str]


@dataclass(slots=True)
class RunSummary:
    run_id: str
    run_dir: Path
    started_at: datetime
    finished_at: datetime
    source_kind: str
    source_label: str
    source_repo_url: str | None
    requested_ref: str | None
    checked_out_ref: str | None
    root_path: Path
    base_url: str
    model_name: str
    api_style: str
    scan_mode: str
    total_files_scanned: int
    total_files_skipped: int
    total_chunks_sent: int
    findings_by_severity: dict[str, int]
    top_files: list[tuple[str, int]]
    errors: list[str]
    research_enabled: bool = False
    total_dependencies_researched: int = 0
    vulnerable_dependencies: int = 0
    searched_dependencies: int = 0
