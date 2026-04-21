from pathlib import Path
import tempfile
import unittest

from vibe_code_scanner.models import (
    ApiStyle,
    AppConfig,
    CodeChunk,
    ScanMode,
    SourceFile,
    TokenizerMode,
)
from vibe_code_scanner.parser import normalize_findings, parse_findings


def make_config(root: Path) -> AppConfig:
    return AppConfig(
        root_path=root,
        export_dir=root / "out",
        base_url="http://127.0.0.1:8000",
        model_name="test-model",
        api_style=ApiStyle.CHAT_COMPLETIONS,
        scan_mode=ScanMode.SECURITY_AND_QUALITY,
        max_concurrent_requests=2,
        max_tokens_per_request=512,
        chunk_target_tokens=200,
        chunk_overlap_tokens=20,
        request_timeout_seconds=10.0,
        retry_count=1,
        max_file_size_bytes=1024 * 1024,
        include_globs=["**/*.py"],
        exclude_globs=[],
        ignored_directories=[],
        tokenizer_mode=TokenizerMode.HEURISTIC,
    )


class ParserTests(unittest.TestCase):
    def test_parse_findings_accepts_fenced_json_and_normalizes_values(self) -> None:
        response_text = """```json
{
  "findings": [
    {
      "title": "Avoid raw shell execution",
      "category": "style/preference",
      "severity": "low",
      "confidence": "high",
      "line_start": 4,
      "line_end": 6,
      "explanation": "Shelling out is unnecessary here.",
      "evidence": "subprocess.call(...)",
      "remediation": "Use a library API instead."
    }
  ]
}
```"""
        parsed = parse_findings(response_text)

        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0].category.value, "style_preference")

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_file = SourceFile(
                root_path=root,
                path=root / "app.py",
                relative_path="app.py",
                size_bytes=100,
                language_hint="python",
            )
            chunk = CodeChunk(
                chunk_index=1,
                total_chunks=1,
                start_line=1,
                end_line=10,
                text="print('hello')\n",
                estimated_tokens=10,
                overlap_from_previous_tokens=0,
                overlap_from_previous_lines=0,
            )

            normalized = normalize_findings(source_file, chunk, parsed)

        self.assertEqual(normalized[0].line_start, 4)
        self.assertEqual(normalized[0].line_end, 6)
        self.assertEqual(normalized[0].file_path, "app.py")

    def test_parse_findings_repairs_unquoted_keys_and_trailing_commas(self) -> None:
        response_text = """{
  findings: [
    {
      "title": "Unsafe deserialization",
      "category": "security",
      "severity": "critical",
      "confidence": "high",
      "line_start": 8,
      "line_end": 10,
      "explanation": "Untrusted input is deserialized directly.",
      "evidence": "keys.unserialize(req.body)",
      "remediation": "Use safe parsing and validate input.",
    }
  ],
}"""

        parsed = parse_findings(response_text)

        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0].title, "Unsafe deserialization")
        self.assertEqual(parsed[0].severity.value, "critical")

    def test_parse_findings_recovers_final_json_object_after_prose(self) -> None:
        response_text = """The user wants a structured review.
I notice a parser call with options like {replaceEntities: true} in the prose.

{
  "findings": [
    {
      "title": "XXE risk from entity expansion",
      "category": "security",
      "severity": "high",
      "confidence": "high",
      "line_start": 14,
      "line_end": 18,
      "explanation": "External entities are enabled while parsing XML.",
      "evidence": "replaceEntities: true",
      "remediation": "Disable entity expansion and use a hardened XML parser."
    }
  ]
}"""

        parsed = parse_findings(response_text)

        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0].title, "XXE risk from entity expansion")

    def test_parse_findings_ignores_think_block_before_json(self) -> None:
        response_text = """<think>
I should inspect the code carefully before returning the object.
</think>
{"findings": []}"""

        parsed = parse_findings(response_text)

        self.assertEqual(parsed, [])


if __name__ == "__main__":
    unittest.main()
