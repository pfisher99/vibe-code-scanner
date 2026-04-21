"""Configuration loading and validation."""

from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any, Mapping

from .defaults import (
    DEFAULT_API_STYLE,
    DEFAULT_BASE_URL,
    DEFAULT_CHUNK_OVERLAP_TOKENS,
    DEFAULT_CHUNK_TARGET_TOKENS,
    DEFAULT_EXCLUDE_GLOBS,
    DEFAULT_EXPORT_DIR,
    DEFAULT_IGNORED_DIRECTORIES,
    DEFAULT_INCLUDE_GLOBS,
    DEFAULT_MAX_CONCURRENT_REQUESTS,
    DEFAULT_MAX_FILE_SIZE_BYTES,
    DEFAULT_MAX_TOKENS_PER_REQUEST,
    DEFAULT_MIN_P,
    DEFAULT_PRESENCE_PENALTY,
    DEFAULT_REPETITION_PENALTY,
    DEFAULT_RESEARCH_MAX_RESULTS,
    DEFAULT_REQUEST_TIMEOUT_SECONDS,
    DEFAULT_RETRY_COUNT,
    DEFAULT_TEMPERATURE,
    DEFAULT_THINKING_TOKEN_BUDGET,
    DEFAULT_THINKING_TOKEN_BUDGET_ENABLED,
    DEFAULT_TOKENIZER_MODE,
    DEFAULT_TOP_K,
    DEFAULT_TOP_P,
)
from .models import ApiStyle, AppConfig, ScanMode, SearchBackend, TokenizerMode


class ConfigError(ValueError):
    """Raised when configuration cannot be loaded or validated."""


def load_config_file(config_path: Path | None) -> dict[str, Any]:
    if config_path is None:
        return {}
    if not config_path.exists():
        raise ConfigError(f"Config file not found: {config_path}")
    try:
        with config_path.open("rb") as handle:
            raw = tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"Invalid TOML in config file {config_path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError("Configuration root must be a TOML table.")
    raw["__config_dir__"] = str(config_path.resolve().parent)
    return raw


def build_config(raw: Mapping[str, Any]) -> AppConfig:
    config_dir = Path(str(_get(raw, "__config_dir__", "."))).expanduser().resolve()
    root_path = _resolve_path(_get(raw, "root_path", "."), config_dir)
    export_dir = _resolve_path(_get(raw, "export_dir", DEFAULT_EXPORT_DIR), config_dir)
    base_url = str(_get(raw, "base_url", DEFAULT_BASE_URL)).strip()
    model_name = str(_get(raw, "model_name", "")).strip()
    api_style = _parse_api_style(_get(raw, "api_style", DEFAULT_API_STYLE))
    scan_mode = _parse_scan_mode(_get(raw, "scan_mode", ScanMode.SECURITY_AND_QUALITY.value))
    include_globs = _coerce_str_list(_get(raw, "include_globs", DEFAULT_INCLUDE_GLOBS))
    exclude_globs = _coerce_str_list(_get(raw, "exclude_globs", DEFAULT_EXCLUDE_GLOBS))
    ignored_directories = _coerce_str_list(
        _get(raw, "ignored_directories", DEFAULT_IGNORED_DIRECTORIES)
    )
    api_key = str(_get(raw, "api_key", os.environ.get("OPENAI_API_KEY", ""))).strip() or None

    config = AppConfig(
        root_path=root_path,
        export_dir=export_dir,
        base_url=base_url,
        model_name=model_name,
        api_style=api_style,
        scan_mode=scan_mode,
        max_concurrent_requests=_positive_int(
            _get(raw, "max_concurrent_requests", DEFAULT_MAX_CONCURRENT_REQUESTS),
            "max_concurrent_requests",
        ),
        max_tokens_per_request=_positive_int(
            _get(raw, "max_tokens_per_request", DEFAULT_MAX_TOKENS_PER_REQUEST),
            "max_tokens_per_request",
        ),
        chunk_target_tokens=_positive_int(
            _get(raw, "chunk_target_tokens", DEFAULT_CHUNK_TARGET_TOKENS),
            "chunk_target_tokens",
        ),
        chunk_overlap_tokens=_non_negative_int(
            _get(raw, "chunk_overlap_tokens", DEFAULT_CHUNK_OVERLAP_TOKENS),
            "chunk_overlap_tokens",
        ),
        request_timeout_seconds=_positive_float(
            _get(raw, "request_timeout_seconds", DEFAULT_REQUEST_TIMEOUT_SECONDS),
            "request_timeout_seconds",
        ),
        retry_count=_non_negative_int(_get(raw, "retry_count", DEFAULT_RETRY_COUNT), "retry_count"),
        max_file_size_bytes=_positive_int(
            _get(raw, "max_file_size_bytes", DEFAULT_MAX_FILE_SIZE_BYTES),
            "max_file_size_bytes",
        ),
        include_globs=include_globs,
        exclude_globs=exclude_globs,
        ignored_directories=ignored_directories,
        api_key=api_key,
        trace_enabled=_parse_bool(_get(raw, "trace", False), "trace"),
        research_enabled=_parse_bool(_get(raw, "research", False), "research"),
        search_backend=_parse_search_backend(_get(raw, "search_backend", SearchBackend.NONE.value)),
        search_base_url=_parse_optional_str(_get(raw, "search_base_url", None)),
        research_max_results=_positive_int(
            _get(raw, "research_max_results", DEFAULT_RESEARCH_MAX_RESULTS),
            "research_max_results",
        ),
        tokenizer_mode=_parse_tokenizer_mode(_get(raw, "tokenizer_mode", DEFAULT_TOKENIZER_MODE)),
        temperature=_non_negative_float(_get(raw, "temperature", DEFAULT_TEMPERATURE), "temperature"),
        top_p=_probability_float(_get(raw, "top_p", DEFAULT_TOP_P), "top_p"),
        top_k=_non_negative_int(_get(raw, "top_k", DEFAULT_TOP_K), "top_k"),
        min_p=_probability_float(_get(raw, "min_p", DEFAULT_MIN_P), "min_p"),
        presence_penalty=_float_value(_get(raw, "presence_penalty", DEFAULT_PRESENCE_PENALTY), "presence_penalty"),
        repetition_penalty=_positive_float(
            _get(raw, "repetition_penalty", DEFAULT_REPETITION_PENALTY),
            "repetition_penalty",
        ),
        thinking_token_budget_enabled=_parse_bool(
            _get(raw, "thinking_token_budget_enabled", DEFAULT_THINKING_TOKEN_BUDGET_ENABLED),
            "thinking_token_budget_enabled",
        ),
        thinking_token_budget=_positive_int(
            _get(raw, "thinking_token_budget", DEFAULT_THINKING_TOKEN_BUDGET),
            "thinking_token_budget",
        ),
        research_max_tokens_per_request=_optional_positive_int(
            _get(raw, "research_max_tokens_per_request", None),
            "research_max_tokens_per_request",
        ),
        research_thinking_token_budget=_optional_positive_int(
            _get(raw, "research_thinking_token_budget", None),
            "research_thinking_token_budget",
        ),
        max_files=_optional_positive_int(_get(raw, "max_files", None), "max_files"),
    )
    _validate_config(config)
    return config


def load_app_config(config_path: Path | None, overrides: Mapping[str, Any] | None = None) -> AppConfig:
    raw = load_config_file(config_path)
    merged = dict(raw)
    if overrides:
        for key, value in overrides.items():
            if value is not None:
                merged[key] = value
    return build_config(merged)


def _get(mapping: Mapping[str, Any], key: str, default: Any) -> Any:
    return mapping.get(key, default)


def _coerce_str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return [item.strip() for item in value if item.strip()]
    raise ConfigError(f"Expected a list of strings, got {type(value).__name__}.")


def _positive_int(value: Any, field_name: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{field_name} must be an integer.") from exc
    if parsed <= 0:
        raise ConfigError(f"{field_name} must be greater than zero.")
    return parsed


def _optional_positive_int(value: Any, field_name: str) -> int | None:
    if value in (None, "", 0, "0"):
        return None
    return _positive_int(value, field_name)


def _non_negative_int(value: Any, field_name: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{field_name} must be an integer.") from exc
    if parsed < 0:
        raise ConfigError(f"{field_name} must be zero or greater.")
    return parsed


def _positive_float(value: Any, field_name: str) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{field_name} must be a number.") from exc
    if parsed <= 0:
        raise ConfigError(f"{field_name} must be greater than zero.")
    return parsed


def _non_negative_float(value: Any, field_name: str) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{field_name} must be a number.") from exc
    if parsed < 0:
        raise ConfigError(f"{field_name} must be zero or greater.")
    return parsed


def _probability_float(value: Any, field_name: str) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{field_name} must be a number.") from exc
    if parsed < 0 or parsed > 1:
        raise ConfigError(f"{field_name} must be between 0 and 1.")
    return parsed


def _float_value(value: Any, field_name: str) -> float:
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{field_name} must be a number.") from exc


def _parse_bool(value: Any, field_name: str) -> bool:
    if isinstance(value, bool):
        return value
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off", ""}:
        return False
    raise ConfigError(f"{field_name} must be a boolean.")


def _parse_optional_str(value: Any) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip()
    return normalized or None


def _parse_scan_mode(value: Any) -> ScanMode:
    normalized = str(value).strip().lower()
    aliases = {
        "security": ScanMode.SECURITY,
        "security_only": ScanMode.SECURITY,
        "both": ScanMode.SECURITY_AND_QUALITY,
        "security_and_quality": ScanMode.SECURITY_AND_QUALITY,
    }
    try:
        return aliases[normalized]
    except KeyError as exc:
        options = ", ".join(sorted(aliases))
        raise ConfigError(f"scan_mode must be one of: {options}") from exc


def _parse_api_style(value: Any) -> ApiStyle:
    normalized = str(value).strip().lower()
    try:
        return ApiStyle(normalized)
    except ValueError as exc:
        options = ", ".join(style.value for style in ApiStyle)
        raise ConfigError(f"api_style must be one of: {options}") from exc


def _parse_search_backend(value: Any) -> SearchBackend:
    normalized = str(value).strip().lower()
    try:
        return SearchBackend(normalized)
    except ValueError as exc:
        options = ", ".join(backend.value for backend in SearchBackend)
        raise ConfigError(f"search_backend must be one of: {options}") from exc


def _parse_tokenizer_mode(value: Any) -> TokenizerMode:
    normalized = str(value).strip().lower()
    try:
        return TokenizerMode(normalized)
    except ValueError as exc:
        options = ", ".join(mode.value for mode in TokenizerMode)
        raise ConfigError(f"tokenizer_mode must be one of: {options}") from exc


def _validate_config(config: AppConfig) -> None:
    if not config.root_path.exists():
        raise ConfigError(f"Scan root does not exist: {config.root_path}")
    if not config.root_path.is_dir():
        raise ConfigError(f"Scan root must be a directory: {config.root_path}")
    if not config.base_url:
        raise ConfigError("base_url cannot be empty.")
    if not config.model_name:
        raise ConfigError("model_name cannot be empty.")
    if config.chunk_overlap_tokens >= config.chunk_target_tokens:
        raise ConfigError("chunk_overlap_tokens must be smaller than chunk_target_tokens.")
    if not config.include_globs:
        raise ConfigError("include_globs must contain at least one pattern.")
    if config.search_backend == SearchBackend.SEARXNG and not config.search_base_url:
        raise ConfigError("search_base_url is required when search_backend is set to searxng.")


def _resolve_path(value: Any, base_dir: Path) -> Path:
    candidate = Path(str(value)).expanduser()
    if not candidate.is_absolute():
        candidate = base_dir / candidate
    return candidate.resolve()
