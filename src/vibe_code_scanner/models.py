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
    DUCKDUCKGO = "duckduckgo"


class TokenizerMode(StrEnum):
    AUTO = "auto"
    VLLM = "vllm"
    HEURISTIC = "heuristic"


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
    research_enabled: bool = False
    search_backend: SearchBackend = SearchBackend.NONE
    search_base_url: str | None = None
    research_max_results: int = 3
    tokenizer_mode: TokenizerMode = TokenizerMode.AUTO
    temperature: float = 0.6
    top_p: float = 0.95
    top_k: int = 20
    min_p: float = 0.0
    presence_penalty: float = 0.0
    repetition_penalty: float = 1.0
    thinking_token_budget_enabled: bool = True
    thinking_token_budget: int = 4096
    research_max_tokens_per_request: int | None = None
    research_thinking_token_budget: int | None = None
    max_files: int | None = None

    def effective_research_max_tokens_per_request(self) -> int:
        return self.research_max_tokens_per_request or (self.max_tokens_per_request * 2)

    def effective_research_thinking_token_budget(self) -> int | None:
        if not self.thinking_token_budget_enabled:
            return None
        return self.research_thinking_token_budget or (self.thinking_token_budget * 2)


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


@dataclass(slots=True)
class ResearchReference:
    title: str
    url: str
    snippet: str = ""


@dataclass(slots=True)
class ResearchToolCall:
    step: int
    action: str
    argument: str | None
    result_preview: str
    success: bool = True


@dataclass(slots=True)
class ResearchSummary:
    report_markdown: str
    tool_calls: list[ResearchToolCall] = field(default_factory=list)
    references: list[ResearchReference] = field(default_factory=list)
    files_consulted: list[str] = field(default_factory=list)
    search_queries: list[str] = field(default_factory=list)
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
    research_tool_calls: int = 0
    research_search_queries: int = 0
    research_references_collected: int = 0
    max_files_limit: int | None = None
    eligible_files_before_limit: int | None = None
