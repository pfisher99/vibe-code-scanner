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
            source_path = root / "app.py"
            source_path.write_text("subprocess.run(user_input, shell=True)\n", encoding="utf-8")
            source_file = SourceFile(root, source_path, "app.py", 32, "python")
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
                    '{"action":"read_source_file","file_path":"app.py"}',
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

        self.assertEqual(len(summary.tool_calls), 3)
        self.assertEqual([call.action for call in summary.tool_calls], ["list_findings", "read_file_report", "read_source_file"])
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

    def test_read_source_file_is_paged_and_line_numbered_for_high_findings(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = make_config(root)
            config.chunk_target_tokens = 40
            source_path = root / "app.py"
            source_path.write_text(
                "\n".join(f"print('line {index}')  # shell=True context" for index in range(1, 21)),
                encoding="utf-8",
            )
            source_file = SourceFile(root, source_path, "app.py", 32, "python")
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

            researcher = PostScanResearcher(config)
            first_section = researcher._read_source_file(file_results, "app.py", section_index=1)
            second_section = researcher._read_source_file(
                file_results,
                "app.py",
                section_index=int(first_section["next_section_index"]),
            )

        self.assertTrue(first_section["truncated"])
        self.assertGreater(first_section["total_sections"], 1)
        self.assertTrue(first_section["source_code"].startswith("1:") or "     1:" in first_section["source_code"])
        self.assertEqual(first_section["eligible_findings"][0]["severity"], "high")
        self.assertEqual(second_section["section_index"], 2)
        self.assertNotEqual(first_section["source_code"], second_section["source_code"])

    def test_read_source_file_rejects_lower_severity_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_path = root / "app.py"
            source_path.write_text("print('hello')\n", encoding="utf-8")
            source_file = SourceFile(root, source_path, "app.py", 32, "python")
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
                            title="Weak signal",
                            category=Category.SECURITY,
                            severity=Severity.MEDIUM,
                            confidence=Confidence.MEDIUM,
                            line_start=1,
                            line_end=1,
                            explanation="Test finding.",
                            evidence="print('hello')",
                            remediation="Review manually.",
                        )
                    ],
                    errors=[],
                )
            ]

            result = PostScanResearcher(make_config(root))._read_source_file(file_results, "app.py")

        self.assertIn("not eligible", result["error"])

    def test_read_repository_file_can_read_unflagged_helper_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            helper_path = root / "helpers.py"
            helper_path.write_text(
                "def helper(user_input):\n    return user_input.strip()\n",
                encoding="utf-8",
            )
            researcher = PostScanResearcher(make_config(root))

            result = researcher._read_repository_file("helpers.py")

        self.assertEqual(result["file_path"], "helpers.py")
        self.assertEqual(result["language_hint"], "python")
        self.assertIn("def helper", result["file_contents"])

    def test_search_code_finds_matches_across_repository_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = make_config(root)
            config.chunk_target_tokens = 2000
            config.research_max_steps = 4
            (root / "app.py").write_text(
                "from helpers import dangerous_helper\n\n"
                "def handle_request(user_input):\n"
                "    return dangerous_helper(user_input)\n",
                encoding="utf-8",
            )
            (root / "helpers.py").write_text(
                "def dangerous_helper(value):\n"
                "    return value.strip()\n",
                encoding="utf-8",
            )
            researcher = PostScanResearcher(config)

            result = researcher._search_code("dangerous_helper")

        self.assertEqual(result["query"], "dangerous_helper")
        self.assertEqual(result["files_with_matches"], 2)
        self.assertIn("app.py", result["matched_files"])
        self.assertIn("helpers.py", result["matched_files"])
        self.assertIn("dangerous_helper", result["search_results"])

    def test_trace_symbol_finds_definitions_and_callers_across_repo(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = make_config(root)
            config.chunk_target_tokens = 2000
            config.research_max_steps = 4
            (root / "helpers.py").write_text(
                "def verify_timestamp(request):\n"
                "    return request is not None\n",
                encoding="utf-8",
            )
            (root / "app.py").write_text(
                "from helpers import verify_timestamp\n\n"
                "def authenticate(request):\n"
                "    return verify_timestamp(request)\n",
                encoding="utf-8",
            )
            (root / "worker.py").write_text(
                "from helpers import verify_timestamp\n\n"
                "def replay_request(request):\n"
                "    return verify_timestamp(request)\n",
                encoding="utf-8",
            )
            researcher = PostScanResearcher(config)

            result = researcher._trace_symbol("verify_timestamp")

        self.assertEqual(result["symbol"], "verify_timestamp")
        self.assertGreaterEqual(result["definition_hits"], 1)
        self.assertGreaterEqual(result["call_hits"], 2)
        self.assertIn("helpers.py", result["files_touched"])
        self.assertIn("authenticate (app.py)", result["candidate_callers"])
        self.assertIn("replay_request (worker.py)", result["candidate_callers"])
        self.assertIn("verify_timestamp", result["trace_report"])

    def test_post_scan_researcher_can_use_search_results(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = make_config(root)
            config.search_backend = SearchBackend.SEARXNG
            config.search_base_url = "http://search.local"
            config.research_max_tokens_per_request = 2048
            config.research_thinking_token_budget = 8192
            source_path = root / "app.py"
            source_path.write_text("subprocess.run(user_input, shell=True)\n", encoding="utf-8")
            source_file = SourceFile(root, source_path, "app.py", 32, "python")
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
                    '{"action":"read_source_file","file_path":"app.py"}',
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
        self.assertEqual(
            [call.action for call in summary.tool_calls],
            ["list_findings", "read_file_report", "search_web", "fetch_url", "read_source_file"],
        )
        self.assertEqual(client.calls[0]["max_tokens_per_request"], 2048)
        self.assertEqual(client.calls[0]["thinking_token_budget"], 8192)

    def test_post_scan_researcher_can_trace_repo_code_and_read_helper_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = make_config(root)
            config.chunk_target_tokens = 2000
            config.research_max_steps = 6
            source_path = root / "app.py"
            source_path.write_text(
                "from helpers import dangerous_helper\n\n"
                "def handle_request(user_input):\n"
                "    return dangerous_helper(user_input)\n",
                encoding="utf-8",
            )
            (root / "helpers.py").write_text(
                "def dangerous_helper(value):\n"
                "    return value.strip()\n",
                encoding="utf-8",
            )
            source_file = SourceFile(root, source_path, "app.py", 64, "python")
            report_path = root / "app.py.md"
            report_path.write_text("# app.py\n\n## Findings\n\n- dangerous helper path\n", encoding="utf-8")
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
                            line_start=4,
                            line_end=4,
                            explanation="Test finding.",
                            evidence="dangerous_helper(user_input)",
                            remediation="Review helper flow.",
                        )
                    ],
                    errors=[],
                )
            ]
            client = _StubClient(
                [
                    '{"action":"list_findings"}',
                    '{"action":"read_file_report","file_path":"app.py"}',
                    '{"action":"trace_symbol","symbol":"dangerous_helper"}',
                    '{"action":"read_repository_file","file_path":"helpers.py"}',
                    '{"action":"read_source_file","file_path":"app.py"}',
                    '{"action":"finish","report_markdown":"# Final Research Report\\n\\nTrace the helper path before remediation."}',
                ]
            )

            summary = asyncio.run(
                PostScanResearcher(config).run(
                    client,
                    file_results,
                    ScanSourceMetadata(kind=ScanSourceKind.LOCAL_PATH, label=str(root)),
                )
            )

        self.assertEqual(
            [call.action for call in summary.tool_calls],
            [
                "list_findings",
                "read_file_report",
                "trace_symbol",
                "read_repository_file",
                "read_source_file",
            ],
        )
        self.assertEqual(summary.files_consulted, ["app.py", "helpers.py"])
        self.assertIn("Trace the helper path before remediation.", summary.report_markdown)

    def test_medium_findings_do_not_require_source_reinspection(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_path = root / "app.py"
            source_path.write_text("print('hello')\n", encoding="utf-8")
            source_file = SourceFile(root, source_path, "app.py", 32, "python")
            report_path = root / "app.py.md"
            report_path.write_text("# app.py\n\n## Findings\n\n- manual review\n", encoding="utf-8")
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
                            title="Needs manual review",
                            category=Category.SECURITY,
                            severity=Severity.MEDIUM,
                            confidence=Confidence.MEDIUM,
                            line_start=1,
                            line_end=1,
                            explanation="Test finding.",
                            evidence="print('hello')",
                            remediation="Review manually.",
                        )
                    ],
                    errors=[],
                )
            ]
            client = _StubClient(
                [
                    '{"action":"list_findings"}',
                    '{"action":"read_file_report","file_path":"app.py"}',
                    '{"action":"finish","report_markdown":"# Final Research Report\\n\\nDone."}',
                ]
            )

            summary = asyncio.run(
                PostScanResearcher(make_config(root)).run(
                    client,
                    file_results,
                    ScanSourceMetadata(kind=ScanSourceKind.LOCAL_PATH, label=str(root)),
                )
            )

        self.assertEqual([call.action for call in summary.tool_calls], ["list_findings", "read_file_report"])

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
            config.research_max_steps = 4
            source_path = root / "app.py"
            source_path.write_text("subprocess.run(user_input, shell=True)\n", encoding="utf-8")
            source_file = SourceFile(root, source_path, "app.py", 32, "python")
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
                    '{"action":"read_source_file","file_path":"app.py"}',
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

    def test_research_progress_logs_without_trace_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = make_config(root)
            config.research_max_steps = 4
            source_path = root / "app.py"
            source_path.write_text("subprocess.run(user_input, shell=True)\n", encoding="utf-8")
            source_file = SourceFile(root, source_path, "app.py", 32, "python")
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
                enabled=False,
                logger=logging.getLogger("vibe_code_scanner"),
                max_slots=2,
            )
            client = _StubClient(
                [
                    '{"action":"list_findings"}',
                    '{"action":"read_file_report","file_path":"app.py"}',
                    '{"action":"read_source_file","file_path":"app.py"}',
                    '{"action":"finish","report_markdown":"# Final Research Report\\n\\nDone."}',
                ]
            )

            with self.assertLogs("vibe_code_scanner", level="INFO") as captured_logs:
                asyncio.run(
                    PostScanResearcher(config).run(
                        client,
                        file_results,
                        ScanSourceMetadata(kind=ScanSourceKind.LOCAL_PATH, label=str(root)),
                        trace_recorder=trace_recorder,
                    )
                )

        joined_logs = "\n".join(captured_logs.output)
        self.assertIsNone(trace_recorder.events_path)
        self.assertIn("[progress] research_step_started research step 1/4", joined_logs)
        self.assertIn("[progress] research_action_parsed research step 1/4", joined_logs)
        self.assertIn("action=read_file_report", joined_logs)
        self.assertIn("argument=app.py", joined_logs)
        self.assertIn("[progress] research_tool_executed research step 3/4", joined_logs)
        self.assertIn("[progress] research_finished research step 4/4", joined_logs)
        self.assertNotIn("research_request_started", joined_logs)
        self.assertNotIn("slot_acquired", joined_logs)


class _StubClient:
    def __init__(self, responses: list[str]) -> None:
        self._responses = iter(responses)
        self.calls: list[dict[str, object]] = []

    async def analyze_messages(self, _messages, **_kwargs):
        self.calls.append(dict(_kwargs))
        return next(self._responses), {"id": "stub"}, None


if __name__ == "__main__":
    unittest.main()
