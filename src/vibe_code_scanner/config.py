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
    DEFAULT_REQUEST_TIMEOUT_SECONDS,
    DEFAULT_RETRY_COUNT,
)
from .models import ApiStyle, AppConfig, ScanMode


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


def _resolve_path(value: Any, base_dir: Path) -> Path:
    candidate = Path(str(value)).expanduser()
    if not candidate.is_absolute():
        candidate = base_dir / candidate
    return candidate.resolve()
