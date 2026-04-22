from pathlib import Path
import asyncio
import json
import logging
import tempfile
import unittest
from unittest.mock import patch

from vibe_code_scanner.models import (
    ApiStyle,
    AppConfig,
    Category,
    Confidence,
    FileScanResult,
    NormalizedFinding,
    ScanMode,
    ScanSourceKind,
    ScanSourceMetadata,
    SearchBackend,
    Severity,
    SourceFile,
    TokenizerMode,
)
from vibe_code_scanner.research import PostScanResearcher
from vibe_code_scanner.tracing import TraceRecorder


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
        research_enabled=True,
        search_backend=SearchBackend.NONE,
        search_base_url=None,
        research_max_results=2,
        tokenizer_mode=TokenizerMode.HEURISTIC,
    )


class ResearchTests(unittest.TestCase):
    def test_post_scan_researcher_runs_tool_loop_over_scan_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_file = SourceFile(root, root / "app.py", "app.py", 32, "python")
            report_path = root / "app.py.md"
            report_path.write_text("# app.py\n\n## Findings\n\n- shell=True\n", encoding="utf-8")
            file_results = [
                FileScanResult(
                    source_file=source_file,
                    report_path=report_path,
                    raw_artifact_path=None,
                    chunks_scanned=1,
                    findings=[
                        NormalizedFinding(
                            file_path="app.py",
                            chunk_ids=[1],
                            title="Potential command injection",
                            category=Category.SECURITY,
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            line_start=1,
                            line_end=1,
                            explanation="Test finding.",
                            evidence="shell=True",
                            remediation="Avoid shell execution.",
                        )
                    ],
                    errors=[],
                )
            ]

            client = _StubClient(
                [
                    'I will inspect the findings first.\n{"action":"list_findings"}',
                    'The report matters more than speculation.\n{"action":"read_file_report","file_path":"app.py"}',
                    '{"action":"finish","report_markdown":"# Final Research Report\\n\\nInvestigate command execution first."}',
                ]
            )

            summary = asyncio.run(
                PostScanResearcher(make_config(root)).run(
                    client,
                    file_results,
                    ScanSourceMetadata(kind=ScanSourceKind.LOCAL_PATH, label=str(root)),
                )
            )

        self.assertEqual(len(summary.tool_calls), 2)
        self.assertEqual(summary.files_consulted, ["app.py"])
        self.assertIn("Investigate command execution first.", summary.report_markdown)

    def test_read_file_report_is_paged_by_token_budget(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = make_config(root)
            config.chunk_target_tokens = 40
            source_file = SourceFile(root, root / "app.py", "app.py", 32, "python")
            report_path = root / "app.py.md"
            report_path.write_text(
                "\n".join(f"- Finding line {index}: shell=True and subprocess usage" for index in range(1, 21)),
                encoding="utf-8",
            )
            file_results = [
                FileScanResult(
                    source_file=source_file,
                    report_path=report_path,
                    raw_artifact_path=None,
                    chunks_scanned=1,
                    findings=[],
                    errors=[],
                )
            ]

            researcher = PostScanResearcher(config)
            first_section = researcher._read_file_report(file_results, "app.py", section_index=1)
            second_section = researcher._read_file_report(
                file_results,
                "app.py",
                section_index=int(first_section["next_section_index"]),
            )

        self.assertTrue(first_section["truncated"])
        self.assertGreater(first_section["total_sections"], 1)
        self.assertEqual(first_section["section_index"], 1)
        self.assertEqual(second_section["section_index"], 2)
        self.assertNotEqual(first_section["report_markdown"], second_section["report_markdown"])

    def test_post_scan_researcher_can_use_search_results(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = make_config(root)
            config.search_backend = SearchBackend.SEARXNG
            config.search_base_url = "http://search.local"
            config.research_max_tokens_per_request = 2048
            config.research_thinking_token_budget = 8192
            source_file = SourceFile(root, root / "app.py", "app.py", 32, "python")
            report_path = root / "app.py.md"
            report_path.write_text("# app.py\n", encoding="utf-8")
            file_results = [
                FileScanResult(
                    source_file=source_file,
                    report_path=report_path,
                    raw_artifact_path=None,
                    chunks_scanned=1,
                    findings=[
                        NormalizedFinding(
                            file_path="app.py",
                            chunk_ids=[1],
                            title="Potential command injection",
                            category=Category.SECURITY,
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            line_start=1,
                            line_end=1,
                            explanation="Test finding.",
                            evidence="shell=True",
                            remediation="Avoid shell execution.",
                        )
                    ],
                    errors=[],
                )
            ]
            client = _StubClient(
                [
                    '{"action":"finish","report_markdown":"# Final Research Report\\n\\nDone too early."}',
                    '{"action":"list_findings"}',
                    '{"action":"read_file_report","file_path":"app.py"}',
                    '{"action":"search_web","query":"python shell true command injection"}',
                    '{"action":"fetch_url","url":"https://owasp.org/example"}',
                    '{"action":"finish","report_markdown":"# Final Research Report\\n\\nDone."}',
                ]
            )

            with (
                patch.object(
                    PostScanResearcher,
                    "_fetch_json",
                    return_value={
                        "results": [
                            {
                                "title": "OWASP Command Injection",
                                "url": "https://owasp.org/example",
                                "content": "Overview of command injection risks.",
                            }
                        ]
                    },
                ),
                patch.object(
                    PostScanResearcher,
                    "_fetch_url_sync",
                    return_value={
                        "url": "https://owasp.org/example",
                        "title": "OWASP Command Injection",
                        "section_index": 1,
                        "total_sections": 1,
                        "content_excerpt": "Command injection guidance from OWASP.",
                        "truncated": False,
                        "next_section_index": None,
                    },
                ),
            ):
                summary = asyncio.run(
                    PostScanResearcher(config).run(
                        client,
                        file_results,
                        ScanSourceMetadata(kind=ScanSourceKind.LOCAL_PATH, label=str(root)),
                    )
                )

        self.assertEqual(summary.search_queries, ["python shell true command injection"])
        self.assertEqual(len(summary.references), 1)
        self.assertEqual(summary.references[0].title, "OWASP Command Injection")
        self.assertEqual(summary.files_consulted, ["app.py"])
        self.assertEqual([call.action for call in summary.tool_calls], ["list_findings", "read_file_report", "search_web", "fetch_url"])
        self.assertEqual(client.calls[0]["max_tokens_per_request"], 2048)
        self.assertEqual(client.calls[0]["thinking_token_budget"], 8192)

    def test_duckduckgo_search_results_are_parsed_without_extra_service(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = make_config(root)
            config.search_backend = SearchBackend.DUCKDUCKGO
            researcher = PostScanResearcher(config)

            with patch.object(
                PostScanResearcher,
                "_fetch_text",
                return_value="""
                <html><body>
                  <a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fowasp.org%2Fwww-project-web-security-testing-guide%2F">OWASP WSTG</a>
                  <a class="result__snippet">Web security testing guidance from OWASP.</a>
                  <a class="result__a" href="https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP">MDN CSP</a>
                  <div class="result__snippet">Content Security Policy documentation.</div>
                </body></html>
                """,
            ):
                results = researcher._search_web_sync("xss csp guidance")

        self.assertEqual(results["query"], "xss csp guidance")
        self.assertEqual(len(results["results"]), 2)
        self.assertEqual(results["results"][0]["url"], "https://owasp.org/www-project-web-security-testing-guide/")
        self.assertEqual(results["results"][0]["title"], "OWASP WSTG")
        self.assertIn("OWASP", results["results"][0]["snippet"])

    def test_trace_recorder_captures_research_steps(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = make_config(root)
            config.trace_enabled = True
            config.research_max_steps = 3
            source_file = SourceFile(root, root / "app.py", "app.py", 32, "python")
            report_path = root / "app.py.md"
            report_path.write_text("# app.py\n\n## Findings\n\n- shell=True\n", encoding="utf-8")
            file_results = [
                FileScanResult(
                    source_file=source_file,
                    report_path=report_path,
                    raw_artifact_path=None,
                    chunks_scanned=1,
                    findings=[
                        NormalizedFinding(
                            file_path="app.py",
                            chunk_ids=[1],
                            title="Potential command injection",
                            category=Category.SECURITY,
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            line_start=1,
                            line_end=1,
                            explanation="Test finding.",
                            evidence="shell=True",
                            remediation="Avoid shell execution.",
                        )
                    ],
                    errors=[],
                )
            ]
            trace_recorder = TraceRecorder(
                root,
                enabled=True,
                logger=logging.getLogger("vibe_code_scanner"),
                max_slots=2,
            )
            client = _StubClient(
                [
                    '{"action":"list_findings"}',
                    '{"action":"read_file_report","file_path":"app.py"}',
                    '{"action":"finish","report_markdown":"# Final Research Report\\n\\nDone."}',
                ]
            )

            asyncio.run(
                PostScanResearcher(config).run(
                    client,
                    file_results,
                    ScanSourceMetadata(kind=ScanSourceKind.LOCAL_PATH, label=str(root)),
                    trace_recorder=trace_recorder,
                )
            )

            self.assertIsNotNone(trace_recorder.events_path)
            events_path = trace_recorder.events_path
            assert events_path is not None
            events = [
                json.loads(line)
                for line in events_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]

        event_names = [event["event"] for event in events]
        self.assertIn("research_step_started", event_names)
        self.assertIn("research_request_started", event_names)
        self.assertIn("research_request_completed", event_names)
        self.assertIn("research_action_parsed", event_names)
        self.assertIn("research_tool_executed", event_names)
        self.assertIn("research_finished", event_names)
        self.assertTrue(
            any(
                event["event"] == "research_request_started"
                and event.get("slot_id") == 1
                and event.get("step_index") == 1
                for event in events
            )
        )


class _StubClient:
    def __init__(self, responses: list[str]) -> None:
        self._responses = iter(responses)
        self.calls: list[dict[str, object]] = []

    async def analyze_messages(self, _messages, **_kwargs):
        self.calls.append(dict(_kwargs))
        return next(self._responses), {"id": "stub"}, None


if __name__ == "__main__":
    unittest.main()
