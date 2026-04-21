"""Finding normalization and deduplication."""

from __future__ import annotations

from copy import deepcopy
from difflib import SequenceMatcher

from .defaults import CONFIDENCE_ORDER, SEVERITY_ORDER
from .models import NormalizedFinding


def dedupe_findings(findings: list[NormalizedFinding]) -> list[NormalizedFinding]:
    deduped: list[NormalizedFinding] = []
    for finding in sorted(findings, key=_sort_key):
        merged = False
        for existing in deduped:
            if _is_duplicate(existing, finding):
                _merge_into(existing, finding)
                merged = True
                break
        if not merged:
            deduped.append(deepcopy(finding))
    return deduped


def _sort_key(finding: NormalizedFinding) -> tuple:
    severity_rank = SEVERITY_ORDER.index(finding.severity.value)
    line_start = finding.line_start if finding.line_start is not None else 10**9
    return (finding.file_path, severity_rank, line_start, finding.title.lower())


def _is_duplicate(left: NormalizedFinding, right: NormalizedFinding) -> bool:
    if left.file_path != right.file_path:
        return False
    if left.category != right.category:
        return False

    title_similarity = _similarity(left.title, right.title)
    explanation_similarity = _similarity(left.explanation, right.explanation)
    evidence_similarity = _similarity(left.evidence, right.evidence)
    lines_close = _line_ranges_close(left, right)

    strong_text_match = title_similarity >= 0.90
    likely_same_issue = title_similarity >= 0.82 and (explanation_similarity >= 0.72 or evidence_similarity >= 0.72)

    return lines_close and (strong_text_match or likely_same_issue)


def _merge_into(target: NormalizedFinding, incoming: NormalizedFinding) -> None:
    target.chunk_ids = sorted(set(target.chunk_ids + incoming.chunk_ids))
    target.severity = _max_ranked(target.severity.value, incoming.severity.value, SEVERITY_ORDER, target, incoming)
    target.confidence = _max_ranked(
        target.confidence.value,
        incoming.confidence.value,
        CONFIDENCE_ORDER,
        target,
        incoming,
        attribute="confidence",
    )
    target.line_start = _min_optional(target.line_start, incoming.line_start)
    target.line_end = _max_optional(target.line_end, incoming.line_end)
    target.explanation = _pick_richer_text(target.explanation, incoming.explanation)
    target.evidence = _pick_richer_text(target.evidence, incoming.evidence)
    target.remediation = _pick_richer_text(target.remediation, incoming.remediation)


def _similarity(left: str, right: str) -> float:
    if not left or not right:
        return 0.0
    return SequenceMatcher(None, _normalize_text(left), _normalize_text(right)).ratio()


def _normalize_text(value: str) -> str:
    return " ".join(value.lower().split())


def _line_ranges_close(left: NormalizedFinding, right: NormalizedFinding, padding: int = 6) -> bool:
    if left.line_start is None or right.line_start is None:
        return True
    left_end = left.line_end or left.line_start
    right_end = right.line_end or right.line_start
    return not (left_end + padding < right.line_start or right_end + padding < left.line_start)


def _min_optional(left: int | None, right: int | None) -> int | None:
    if left is None:
        return right
    if right is None:
        return left
    return min(left, right)


def _max_optional(left: int | None, right: int | None) -> int | None:
    if left is None:
        return right
    if right is None:
        return left
    return max(left, right)


def _pick_richer_text(left: str, right: str) -> str:
    return right if len(right) > len(left) else left


def _max_ranked(
    left_value: str,
    right_value: str,
    order: list[str],
    target: NormalizedFinding,
    incoming: NormalizedFinding,
    attribute: str = "severity",
):
    left_index = order.index(left_value)
    right_index = order.index(right_value)
    return getattr(incoming if right_index < left_index else target, attribute)
