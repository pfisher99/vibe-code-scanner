"""Structured response parsing and finding normalization."""

from __future__ import annotations

import json
from json import JSONDecodeError

from .models import Category, CodeChunk, Confidence, NormalizedFinding, ParsedFinding, Severity, SourceFile


class ResponseParseError(ValueError):
    """Raised when a model response cannot be parsed into the expected schema."""


def parse_findings(response_text: str) -> list[ParsedFinding]:
    payload = _load_json_payload(response_text)
    findings = payload.get("findings")
    if findings is None:
        raise ResponseParseError("Response JSON did not contain a 'findings' field.")
    if not isinstance(findings, list):
        raise ResponseParseError("Response JSON field 'findings' must be a list.")

    parsed: list[ParsedFinding] = []
    for item in findings:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title", "")).strip()
        if not title:
            continue
        parsed.append(
            ParsedFinding(
                title=title,
                category=_parse_category(item.get("category")),
                severity=_parse_severity(item.get("severity")),
                confidence=_parse_confidence(item.get("confidence")),
                line_start=_parse_optional_int(item.get("line_start")),
                line_end=_parse_optional_int(item.get("line_end")),
                explanation=str(item.get("explanation", "")).strip(),
                evidence=str(item.get("evidence", "")).strip(),
                remediation=str(item.get("remediation", "")).strip(),
            )
        )
    return parsed


def normalize_findings(
    source_file: SourceFile,
    chunk: CodeChunk,
    findings: list[ParsedFinding],
) -> list[NormalizedFinding]:
    normalized: list[NormalizedFinding] = []
    for finding in findings:
        line_start = _clamp_line(finding.line_start, chunk.start_line, chunk.end_line)
        line_end = _clamp_line(finding.line_end, chunk.start_line, chunk.end_line)
        if line_start is not None and line_end is not None and line_end < line_start:
            line_end = line_start
        normalized.append(
            NormalizedFinding(
                file_path=source_file.relative_path,
                chunk_ids=[chunk.chunk_index],
                title=finding.title,
                category=finding.category,
                severity=finding.severity,
                confidence=finding.confidence,
                line_start=line_start,
                line_end=line_end,
                explanation=finding.explanation,
                evidence=finding.evidence,
                remediation=finding.remediation,
            )
        )
    return normalized


def _load_json_payload(response_text: str) -> dict:
    cleaned = response_text.strip()
    if cleaned.startswith("```"):
        cleaned = _strip_code_fences(cleaned)
    try:
        payload = json.loads(cleaned)
    except JSONDecodeError:
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start < 0 or end <= start:
            raise ResponseParseError("Response did not contain valid JSON.")
        try:
            payload = json.loads(cleaned[start : end + 1])
        except JSONDecodeError as exc:
            raise ResponseParseError(f"Response JSON could not be parsed: {exc}") from exc
    if not isinstance(payload, dict):
        raise ResponseParseError("Response JSON root must be an object.")
    return payload


def _strip_code_fences(text: str) -> str:
    lines = text.splitlines()
    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].startswith("```"):
        lines = lines[:-1]
    return "\n".join(lines)


def _parse_category(value: object) -> Category:
    normalized = _normalize_enum_value(value)
    aliases = {
        "security": Category.SECURITY,
        "correctness": Category.CORRECTNESS,
        "maintainability": Category.MAINTAINABILITY,
        "suspicious_pattern": Category.SUSPICIOUS_PATTERN,
        "suspicious pattern": Category.SUSPICIOUS_PATTERN,
        "style_preference": Category.STYLE_PREFERENCE,
        "style preference": Category.STYLE_PREFERENCE,
        "style/preference": Category.STYLE_PREFERENCE,
    }
    return aliases.get(normalized, Category.SUSPICIOUS_PATTERN)


def _parse_severity(value: object) -> Severity:
    normalized = _normalize_enum_value(value)
    return {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }.get(normalized, Severity.INFO)


def _parse_confidence(value: object) -> Confidence:
    normalized = _normalize_enum_value(value)
    return {
        "high": Confidence.HIGH,
        "medium": Confidence.MEDIUM,
        "low": Confidence.LOW,
    }.get(normalized, Confidence.MEDIUM)


def _parse_optional_int(value: object) -> int | None:
    if value in (None, "", 0, "0"):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _normalize_enum_value(value: object) -> str:
    return str(value or "").strip().lower().replace("/", "_")


def _clamp_line(value: int | None, start_line: int, end_line: int) -> int | None:
    if value is None:
        return None
    return max(start_line, min(end_line, value))
