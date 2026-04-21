from pathlib import Path
import tempfile
import unittest

from vibe_code_scanner.discovery import discover_source_files
from vibe_code_scanner.models import ApiStyle, AppConfig, ScanMode


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
        ignored_directories=["node_modules"],
    )


class DiscoveryTests(unittest.TestCase):
    def test_discover_source_files_honors_ignores_and_top_level_globs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "main.py").write_text("print('root')\n", encoding="utf-8")
            (root / "README.md").write_text("# docs\n", encoding="utf-8")
            (root / "src").mkdir()
            (root / "src" / "app.py").write_text("print('nested')\n", encoding="utf-8")
            (root / "node_modules").mkdir()
            (root / "node_modules" / "lib.js").write_text("console.log('skip')\n", encoding="utf-8")

            files, skipped = discover_source_files(make_config(root))

        self.assertEqual([file.relative_path for file in files], ["main.py", "src/app.py"])
        skipped_reasons = {item.relative_path: item.reason for item in skipped}
        self.assertEqual(skipped_reasons["README.md"], "not_included")
        self.assertEqual(skipped_reasons["node_modules"], "ignored_directory")


if __name__ == "__main__":
    unittest.main()
