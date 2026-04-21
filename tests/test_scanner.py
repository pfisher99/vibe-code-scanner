import asyncio
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vibe_code_scanner.models import ApiStyle, AppConfig, ScanMode, ScanSourceKind, ScanSourceMetadata
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

            async def fake_analyze_messages(_self, _messages):
                return (
                    '{"findings":[{"title":"Potential command injection","category":"security",'
                    '"severity":"high","confidence":"high","line_start":2,"line_end":2,'
                    '"explanation":"Untrusted input reaches shell execution.","evidence":"shell=True",'
                    '"remediation":"Pass an argument list and avoid shell=True."}]}',
                    {"id": "fake-response"},
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


if __name__ == "__main__":
    unittest.main()
