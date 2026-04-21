"""Prompt construction for model chunk analysis."""

from __future__ import annotations

from .models import CodeChunk, ScanMode, SourceFile

SYSTEM_PROMPT = """You are reviewing a chunk of source code from a larger repository.

Your task is to identify likely security flaws, correctness risks, suspicious patterns, and notable bad coding practices visible in this chunk alone.

Be conservative. Do not invent issues. Do not assume hidden context unless the shown code strongly implies it. If there are no meaningful findings, return an empty findings array.

Only assess the code shown. Do not speculate about unseen files, hidden frameworks, deployment settings, or runtime behavior unless the shown code makes that risk likely.

Return JSON only. No markdown. No prose outside JSON.
"""

SCHEMA_BLOCK = """JSON schema:
{
  "findings": [
    {
      "title": "string",
      "category": "security|correctness|maintainability|suspicious_pattern|style_preference",
      "severity": "critical|high|medium|low|info",
      "confidence": "high|medium|low",
      "line_start": 0,
      "line_end": 0,
      "explanation": "string",
      "evidence": "string",
      "remediation": "string"
    }
  ]
}"""


def build_messages(source_file: SourceFile, chunk: CodeChunk, scan_mode: ScanMode) -> list[dict[str, str]]:
    mode_block = _mode_block(scan_mode)
    overlap_note = (
        f"This chunk overlaps {chunk.overlap_from_previous_lines} lines "
        f"(about {chunk.overlap_from_previous_tokens} tokens) with the previous chunk."
        if chunk.overlap_from_previous_lines
        else "This is the first chunk for the file and has no previous overlap."
    )
    user_prompt = f"""Repository-relative path: {source_file.relative_path}
Chunk: {chunk.chunk_index} of {chunk.total_chunks}
Approximate file line range covered: {chunk.start_line}-{chunk.end_line}
Approximate input tokens in this chunk: {chunk.estimated_tokens}
Scan mode: {scan_mode.value}
{overlap_note}

Only assess the code shown and do not assume unseen code unless it is explicitly implied here.

Prioritize:
{mode_block}

For each finding, provide:
- short title
- category
- severity
- confidence
- approximate line_start
- approximate line_end
- explanation
- evidence
- remediation

If there are no meaningful findings, return:
{{"findings": []}}

{SCHEMA_BLOCK}

Source code:
```{source_file.language_hint}
{chunk.text}
```"""

    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]


def _mode_block(scan_mode: ScanMode) -> str:
    if scan_mode == ScanMode.SECURITY:
        return """- security vulnerabilities
- dangerous input handling
- authentication or authorization mistakes
- secrets or sensitive data exposure
- injection risks
- unsafe deserialization
- path traversal risks
- command execution risks
- insecure crypto usage
- SSRF, XXE, CSRF, XSS, SQL injection where applicable
- race conditions or dangerous concurrency patterns

Ignore purely stylistic or low-signal maintainability concerns unless they materially increase security risk."""

    return """- security vulnerabilities
- dangerous input handling
- authentication or authorization mistakes
- secrets or sensitive data exposure
- injection risks
- unsafe deserialization
- path traversal risks
- command execution risks
- insecure crypto usage
- SSRF, XXE, CSRF, XSS, SQL injection where applicable
- race conditions or dangerous concurrency patterns
- obvious correctness bugs
- severe maintainability hazards
- suspicious anti-patterns"""
