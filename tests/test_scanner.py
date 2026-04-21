import asyncio
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vibe_code_scanner.models import (
    ApiStyle,
    AppConfig,
    ChunkTraceData,
    DependencyResearchItem,
    DependencyVulnerability,
    ResearchReference,
    ResearchSummary,
    ScanMode,
    ScanSourceKind,
    ScanSourceMetadata,
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
                        used_streaming=False,
                        live_streaming_requested=False,
                        stream_fallback_reason=None,
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
            (root / "package.json").write_text('{"dependencies":{"express":"4.18.2"}}', encoding="utf-8")
            config = make_config(root)
            config.research_enabled = True

            async def fake_analyze_messages(_self, _messages, **_kwargs):
                return ('{"findings":[]}', {"id": "fake-response"}, None)

            research_summary = ResearchSummary(
                dependencies=[
                    DependencyResearchItem(
                        source_file="package.json",
                        ecosystem="npm",
                        name="express",
                        version_spec="4.18.2",
                        resolved_version="4.18.2",
                        latest_version="5.1.0",
                        vulnerabilities=[
                            DependencyVulnerability(
                                id="GHSA-test",
                                summary="Known vulnerability",
                                references=[
                                    ResearchReference(
                                        title="OSV Advisory",
                                        url="https://osv.dev/vulnerability/GHSA-test",
                                    )
                                ],
                            )
                        ],
                    )
                ],
                total_dependencies=1,
                vulnerable_dependencies=1,
                searched_dependencies=0,
            )

            with patch(
                "vibe_code_scanner.client.OpenAICompatibleClient.analyze_messages",
                new=fake_analyze_messages,
            ), patch("vibe_code_scanner.scanner.DependencyResearcher.run", return_value=research_summary):
                summary = asyncio.run(RepositoryScanner(config).run())

            self.assertTrue((summary.run_dir / "research" / "dependencies.md").exists())
            self.assertTrue((summary.run_dir / "raw" / "research" / "dependencies.json").exists())
            self.assertTrue(summary.research_enabled)
            self.assertEqual(summary.total_dependencies_researched, 1)
            index_text = (summary.run_dir / "index.md").read_text(encoding="utf-8")
            self.assertIn("Dependencies researched: `1`", index_text)


if __name__ == "__main__":
    unittest.main()
