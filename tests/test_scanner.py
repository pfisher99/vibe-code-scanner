import asyncio
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vibe_code_scanner.models import (
    ApiStyle,
    AppConfig,
    ChunkTraceData,
    ResearchReference,
    ResearchSummary,
    ResearchToolCall,
    ScanMode,
    ScanSourceKind,
    ScanSourceMetadata,
    TokenizerMode,
)
from vibe_code_scanner.scanner import RepositoryScanner


def make_config(root: Path) -> AppConfig:
    return AppConfig(
        root_path=root,
        export_dir=root / "scan-runs",
        base_url="http://127.0.0.1:8000",
        model_name="test-model",
        api_style=ApiStyle.CHAT_COMPLETIONS,
        scan_mode=ScanMode.SECURITY_AND_QUALITY,
        max_concurrent_requests=2,
        max_tokens_per_request=512,
        chunk_target_tokens=100,
        chunk_overlap_tokens=20,
        request_timeout_seconds=10.0,
        retry_count=1,
        max_file_size_bytes=1024 * 1024,
        include_globs=["**/*.py"],
        exclude_globs=[],
        ignored_directories=[],
        tokenizer_mode=TokenizerMode.HEURISTIC,
    )


class ScannerTests(unittest.TestCase):
    def test_repository_scanner_writes_expected_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "app.py").write_text(
                "import subprocess\nsubprocess.run(user_cmd, shell=True)\n",
                encoding="utf-8",
            )
            config = make_config(root)

            async def fake_analyze_messages(_self, _messages, **_kwargs):
                return (
                    '{"findings":[{"title":"Potential command injection","category":"security",'
                    '"severity":"high","confidence":"high","line_start":2,"line_end":2,'
                    '"explanation":"Untrusted input reaches shell execution.","evidence":"shell=True",'
                    '"remediation":"Pass an argument list and avoid shell=True."}]}',
                    {"id": "fake-response"},
                    None,
                )

            with patch(
                "vibe_code_scanner.client.OpenAICompatibleClient.analyze_messages",
                new=fake_analyze_messages,
            ):
                summary = asyncio.run(
                    RepositoryScanner(
                        config,
                        source_metadata=ScanSourceMetadata(
                            kind=ScanSourceKind.GITHUB_REPO,
                            label="https://github.com/OWASP/NodeGoat.git",
                            repo_url="https://github.com/OWASP/NodeGoat.git",
                            requested_ref="main",
                            checked_out_ref="main",
                        ),
                    ).run()
                )

            self.assertTrue((summary.run_dir / "index.md").exists())
            self.assertTrue((summary.run_dir / "findings.json").exists())
            self.assertTrue((summary.run_dir / "files" / "app.py.md").exists())
            self.assertTrue((summary.run_dir / "raw" / "files" / "app.py.json").exists())
            self.assertEqual(summary.total_files_scanned, 1)
            self.assertEqual(summary.findings_by_severity.get("high"), 1)
            self.assertEqual(summary.source_kind, "github_repo")

            index_text = (summary.run_dir / "index.md").read_text(encoding="utf-8")
            self.assertIn("Scan source type: `github_repo`", index_text)
            self.assertIn("Source repo URL: `https://github.com/OWASP/NodeGoat.git`", index_text)
            self.assertIn("Requested ref: `main`", index_text)
            self.assertIn("Checked out ref: `main`", index_text)

    def test_repository_scanner_logs_file_progress(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "app.py").write_text("print('one')\nprint('two')\n", encoding="utf-8")
            config = make_config(root)

            async def fake_analyze_messages(_self, _messages, **_kwargs):
                return ('{"findings":[]}', {"id": "fake-response"}, None)

            with patch(
                "vibe_code_scanner.client.OpenAICompatibleClient.analyze_messages",
                new=fake_analyze_messages,
            ), self.assertLogs("vibe_code_scanner", level="INFO") as captured_logs:
                asyncio.run(RepositoryScanner(config).run())

            joined_logs = "\n".join(captured_logs.output)
            self.assertIn("Completed app.py: 2 lines scanned. 0/1 files remaining (0.0% remaining).", joined_logs)

    def test_repository_scanner_writes_trace_data_when_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "app.py").write_text("print('trace me')\n", encoding="utf-8")
            config = make_config(root)
            config.trace_enabled = True

            async def fake_analyze_messages(_self, messages, **_kwargs):
                return (
                    '{"findings":[]}',
                    {"id": "fake-response"},
                    ChunkTraceData(
                        request_messages=messages,
                        trace_label="app.py chunk 1/1",
                        slot_id=1,
                        request_message_count=len(messages),
                        request_char_count=sum(len(str(message.get("content", ""))) for message in messages),
                        response_char_count=len('{"findings":[]}'),
                    ),
                )

            with patch(
                "vibe_code_scanner.client.OpenAICompatibleClient.analyze_messages",
                new=fake_analyze_messages,
            ):
                summary = asyncio.run(RepositoryScanner(config).run())

            chunk_artifact = summary.run_dir / "raw" / "chunks" / "app.py.chunk-0001.json"
            chunk_text = chunk_artifact.read_text(encoding="utf-8")
            self.assertIn('"trace": {', chunk_text)
            self.assertIn('"request_messages"', chunk_text)
            self.assertIn('"slot_id": 1', chunk_text)
            self.assertIn('"steps"', chunk_text)
            trace_events = (summary.run_dir / "raw" / "trace" / "events.jsonl").read_text(encoding="utf-8")
            self.assertIn('"event": "chunk_request_started"', trace_events)
            self.assertIn('"event": "chunk_request_completed"', trace_events)
            index_text = (summary.run_dir / "index.md").read_text(encoding="utf-8")
            self.assertIn("Run event stream: [raw/trace/events.jsonl](raw/trace/events.jsonl)", index_text)

    def test_repository_scanner_keeps_chunk_requests_saturated_within_a_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "big.py").write_text(
                "".join(f"line_{index} = '{index:03d}'\n" for index in range(1, 40)),
                encoding="utf-8",
            )
            config = make_config(root)
            config.max_concurrent_requests = 2
            config.chunk_target_tokens = 8
            config.chunk_overlap_tokens = 0

            active_requests = 0
            max_active_requests = 0
            active_lock = asyncio.Lock()

            async def fake_analyze_messages(_self, _messages, **_kwargs):
                nonlocal active_requests, max_active_requests
                async with active_lock:
                    active_requests += 1
                    max_active_requests = max(max_active_requests, active_requests)
                await asyncio.sleep(0.01)
                async with active_lock:
                    active_requests -= 1
                return ('{"findings":[]}', {"id": "fake-response"}, None)

            with patch(
                "vibe_code_scanner.client.OpenAICompatibleClient.analyze_messages",
                new=fake_analyze_messages,
            ):
                asyncio.run(RepositoryScanner(config).run())

            self.assertEqual(max_active_requests, 2)

    def test_repository_scanner_writes_research_outputs_when_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "app.py").write_text("print('hello')\n", encoding="utf-8")
            config = make_config(root)
            config.research_enabled = True

            async def fake_analyze_messages(_self, _messages, **_kwargs):
                return (
                    '{"findings":[{"title":"Potential command injection","category":"security",'
                    '"severity":"high","confidence":"high","line_start":1,"line_end":1,'
                    '"explanation":"Test finding.","evidence":"shell=True",'
                    '"remediation":"Avoid shell execution."}]}',
                    {"id": "fake-response"},
                    None,
                )

            research_summary = ResearchSummary(
                report_markdown="# Final Research Report\n\nFocus on shell execution first.\n",
                tool_calls=[
                    ResearchToolCall(
                        step=1,
                        action="list_findings",
                        argument=None,
                        result_preview='{"total_findings":1}',
                    )
                ],
                references=[
                    ResearchReference(
                        title="OWASP Command Injection",
                        url="https://owasp.org/www-community/attacks/Command_Injection",
                    )
                ],
                files_consulted=["app.py"],
                search_queries=["command injection shell true python"],
            )

            with patch(
                "vibe_code_scanner.client.OpenAICompatibleClient.analyze_messages",
                new=fake_analyze_messages,
            ), patch("vibe_code_scanner.scanner.PostScanResearcher.run", return_value=research_summary):
                summary = asyncio.run(RepositoryScanner(config).run())

            self.assertTrue((summary.run_dir / "research" / "final-report.md").exists())
            self.assertTrue((summary.run_dir / "raw" / "research" / "final-report.json").exists())
            self.assertTrue(summary.research_enabled)
            self.assertEqual(summary.research_tool_calls, 1)
            index_text = (summary.run_dir / "index.md").read_text(encoding="utf-8")
            self.assertIn("Research tool calls: `1`", index_text)

    def test_repository_scanner_can_limit_scan_to_random_subset_of_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            for index in range(1, 5):
                (root / f"file_{index}.py").write_text(f"print({index})\n", encoding="utf-8")
            config = make_config(root)
            config.max_files = 2

            async def fake_analyze_messages(_self, _messages, **_kwargs):
                return ('{"findings":[]}', {"id": "fake-response"}, None)

            with patch(
                "vibe_code_scanner.client.OpenAICompatibleClient.analyze_messages",
                new=fake_analyze_messages,
            ):
                summary = asyncio.run(RepositoryScanner(config).run())

            self.assertEqual(summary.total_files_scanned, 2)
            self.assertEqual(summary.total_files_skipped, 2)
            self.assertEqual(summary.max_files_limit, 2)
            self.assertEqual(summary.eligible_files_before_limit, 4)
            file_reports = sorted((summary.run_dir / "files").glob("*.md"))
            self.assertEqual(len(file_reports), 2)
            index_text = (summary.run_dir / "index.md").read_text(encoding="utf-8")
            self.assertIn("Max files limit: `2`", index_text)


if __name__ == "__main__":
    unittest.main()
