"""Prompt construction for model chunk analysis."""

from __future__ import annotations

from importlib import resources

from .models import CodeChunk, ScanMode, SourceFile

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


def load_system_prompt() -> str:
    return resources.files("vibe_code_scanner").joinpath("scanner_system_prompt.txt").read_text(
        encoding="utf-8"
    ).strip()


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
Chunk token count: {chunk.estimated_tokens}
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

    user_prompt += """

Important response rules:
- Return one JSON object only.
- Use only the allowed category, severity, and confidence values.
- If line numbers are unclear, use 0 for unknown values instead of guessing wildly.
- Do not include explanatory text before or after the JSON object.
- If the chunk looks safe or uncertain, prefer {"findings": []} over a weak claim."""

    if scan_mode == ScanMode.HIGH_SECURITY:
        user_prompt += """
- In high_security mode, report only `security` findings.
- In high_security mode, report only `high` or `critical` severity findings.
- In high_security mode, omit anything uncertain, moderate, low-severity, or non-exploitable."""

    return [
        {"role": "system", "content": load_system_prompt()},
        {"role": "user", "content": user_prompt},
    ]


def _mode_block(scan_mode: ScanMode) -> str:
    if scan_mode == ScanMode.HIGH_SECURITY:
        return """- only concrete, dangerous security vulnerabilities with serious exploit potential
- high-impact auth bypass, authz bypass, or privilege escalation
- command execution, severe injection, unsafe deserialization, or XXE with meaningful impact
- secrets exposure, session flaws, path traversal, SSRF, or crypto misuse when the impact looks severe
- issues that would realistically matter to a human security reviewer triaging only the scariest findings

Ignore medium/low issues, correctness bugs, maintainability, style, suspicious-but-weak patterns, and speculative concerns.
Only report findings that should clearly be categorized as `security` and should clearly be rated `high` or `critical`.
If the issue is security-relevant but not obviously dangerous, do not report it."""

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
