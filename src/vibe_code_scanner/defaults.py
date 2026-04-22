"""Default configuration values and shared constants."""

from __future__ import annotations

DEFAULT_BASE_URL = "http://127.0.0.1:8000"
DEFAULT_EXPORT_DIR = "scan-runs"
DEFAULT_API_STYLE = "chat_completions"
DEFAULT_TOKENIZER_MODE = "auto"
DEFAULT_TEMPERATURE = 0.6
DEFAULT_TOP_P = 0.95
DEFAULT_TOP_K = 20
DEFAULT_MIN_P = 0.0
DEFAULT_PRESENCE_PENALTY = 0.0
DEFAULT_REPETITION_PENALTY = 1.0
DEFAULT_THINKING_TOKEN_BUDGET_ENABLED = True
DEFAULT_THINKING_TOKEN_BUDGET = 4096
DEFAULT_MAX_CONTEXT_MAX_TOKENS_PER_REQUEST = 81_920
DEFAULT_MAX_CONTEXT_TOTAL_CONTEXT_WINDOW_TOKENS = 262_144

DEFAULT_INCLUDE_GLOBS = [
    "**/*.c",
    "**/*.cc",
    "**/*.cpp",
    "**/*.cs",
    "**/*.css",
    "**/*.go",
    "**/*.h",
    "**/*.hpp",
    "**/*.html",
    "**/*.java",
    "**/*.js",
    "**/*.json",
    "**/*.jsx",
    "**/*.kt",
    "**/*.kts",
    "**/*.php",
    "**/*.ps1",
    "**/*.py",
    "**/*.rb",
    "**/*.rs",
    "**/*.scala",
    "**/*.sh",
    "**/*.sql",
    "**/*.svelte",
    "**/*.swift",
    "**/*.tf",
    "**/*.toml",
    "**/*.ts",
    "**/*.tsx",
    "**/*.vue",
    "**/*.xml",
    "**/*.yaml",
    "**/*.yml",
    "**/Dockerfile",
    "**/requirements.txt",
    "**/requirements-*.txt",
]

DEFAULT_EXCLUDE_GLOBS = [
    "**/*.min.css",
    "**/*.min.js",
    "**/*.map",
    "**/*.lock",
    "**/package-lock.json",
    "**/pnpm-lock.yaml",
    "**/yarn.lock",
]

DEFAULT_IGNORED_DIRECTORIES = [
    ".cache",
    ".git",
    ".hg",
    ".idea",
    ".mypy_cache",
    ".next",
    ".nuxt",
    ".pytest_cache",
    ".ruff_cache",
    ".svn",
    ".tox",
    ".venv",
    ".vscode",
    "__pycache__",
    "bin",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "obj",
    "out",
    "site-packages",
    "target",
    "temp",
    "tmp",
    "vendor",
    "venv",
]

DEFAULT_MAX_CONCURRENT_REQUESTS = 4
DEFAULT_MAX_TOKENS_PER_REQUEST = 1200
DEFAULT_CHUNK_TARGET_TOKENS = 1400
DEFAULT_CHUNK_OVERLAP_TOKENS = 160
DEFAULT_REQUEST_TIMEOUT_SECONDS = 300.0
DEFAULT_RETRY_COUNT = 2
DEFAULT_MAX_FILE_SIZE_BYTES = 1_048_576
DEFAULT_BINARY_SAMPLE_SIZE = 4096
DEFAULT_RESEARCH_MAX_RESULTS = 3
DEFAULT_RESEARCH_MAX_STEPS = 12

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
CONFIDENCE_ORDER = ["high", "medium", "low"]

CATEGORY_DISPLAY_NAMES = {
    "security": "Security",
    "correctness": "Correctness",
    "maintainability": "Maintainability",
    "suspicious_pattern": "Suspicious Pattern",
    "style_preference": "Style / Preference",
}

LANGUAGE_HINTS = {
    ".c": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cs": "csharp",
    ".css": "css",
    ".go": "go",
    ".h": "c",
    ".hpp": "cpp",
    ".html": "html",
    ".java": "java",
    ".js": "javascript",
    ".json": "json",
    ".jsx": "jsx",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".php": "php",
    ".ps1": "powershell",
    ".py": "python",
    ".rb": "ruby",
    ".rs": "rust",
    ".scala": "scala",
    ".sh": "bash",
    ".sql": "sql",
    ".svelte": "svelte",
    ".swift": "swift",
    ".tf": "hcl",
    ".toml": "toml",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".vue": "vue",
    ".xml": "xml",
    ".yaml": "yaml",
    ".yml": "yaml",
}
