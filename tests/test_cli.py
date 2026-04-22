import unittest
from argparse import Namespace
from pathlib import Path
import tempfile
from unittest.mock import patch

from vibe_code_scanner.cli import (
    _finalize_local_scan_source,
    _resolve_scan_source,
    _resolve_start_folder,
    build_parser,
    main,
)
from vibe_code_scanner.models import ApiStyle, AppConfig, ScanMode, ScanSourceKind, ScanSourceMetadata, TokenizerMode
from vibe_code_scanner.repo_source import AcquiredRepository
from vibe_code_scanner.config import ConfigError


class CliTests(unittest.TestCase):
    def test_main_rejects_root_and_repo_together(self) -> None:
        with self.assertRaises(SystemExit) as context:
            main([".", "--repo", "https://github.com/OWASP/NodeGoat"])
        self.assertEqual(context.exception.code, 2)

    def test_main_rejects_ref_without_repo(self) -> None:
        with self.assertRaises(SystemExit) as context:
            main(["--ref", "main"])
        self.assertEqual(context.exception.code, 2)

    def test_parser_accepts_max_context_flag(self) -> None:
        args = build_parser().parse_args(["--max-context"])
        self.assertTrue(args.max_context)

    def test_resolve_scan_source_uses_local_root_when_repo_is_not_provided(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            nested = root / "sample-repo"
            nested.mkdir()

            root_override, source_metadata = _resolve_scan_source(
                Namespace(root=str(nested), repo=None, ref=None, start_folder=None),
                temp_repo_dir=None,
            )

        self.assertEqual(root_override, str(nested.resolve()))
        self.assertEqual(source_metadata.kind.value, "local_path")
        self.assertEqual(source_metadata.label, str(nested.resolve()))

    def test_resolve_scan_source_can_narrow_local_scan_to_subfolder(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            nested = root / "sample-repo"
            target = nested / "src"
            target.mkdir(parents=True)

            root_override, source_metadata = _resolve_scan_source(
                Namespace(root=str(nested), repo=None, ref=None, start_folder="src"),
                temp_repo_dir=None,
            )

        self.assertEqual(root_override, str(target.resolve()))
        self.assertEqual(source_metadata.kind, ScanSourceKind.LOCAL_PATH)
        self.assertEqual(source_metadata.label, str(target.resolve()))

    def test_resolve_scan_source_can_narrow_repo_scan_to_subfolder(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            checkout = root / "repo"
            target = checkout / "server"
            target.mkdir(parents=True)

            with patch(
                "vibe_code_scanner.cli.acquire_github_repo",
                return_value=AcquiredRepository(
                    repo_url="https://github.com/example/project",
                    normalized_repo_url="https://github.com/example/project.git",
                    checkout_path=checkout,
                    requested_ref="main",
                    checked_out_ref="main",
                ),
            ):
                root_override, source_metadata = _resolve_scan_source(
                    Namespace(
                        root=None,
                        repo="https://github.com/example/project",
                        ref="main",
                        start_folder="server",
                    ),
                    temp_repo_dir=root,
                )

        self.assertEqual(root_override, str(target.resolve()))
        self.assertEqual(source_metadata.kind, ScanSourceKind.GITHUB_REPO)
        self.assertEqual(source_metadata.label, "https://github.com/example/project.git")

    def test_resolve_start_folder_rejects_paths_outside_source(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with self.assertRaises(ConfigError):
                _resolve_start_folder(root, "..\\outside", flag_name="--folder")

    def test_finalize_local_scan_source_applies_folder_to_config_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "nested"
            target.mkdir()
            config = AppConfig(
                root_path=root,
                export_dir=root / "scan-runs",
                base_url="http://127.0.0.1:8000",
                model_name="test-model",
                api_style=ApiStyle.CHAT_COMPLETIONS,
                scan_mode=ScanMode.SECURITY,
                max_concurrent_requests=1,
                max_tokens_per_request=256,
                chunk_target_tokens=256,
                chunk_overlap_tokens=32,
                request_timeout_seconds=30.0,
                retry_count=1,
                max_file_size_bytes=1024,
                include_globs=["**/*.py"],
                exclude_globs=[],
                ignored_directories=[],
                tokenizer_mode=TokenizerMode.HEURISTIC,
            )

            updated_metadata = _finalize_local_scan_source(
                config,
                ScanSourceMetadata(kind=ScanSourceKind.LOCAL_PATH, label="config root_path"),
                "nested",
                root_override=None,
            )

        self.assertEqual(config.root_path, target.resolve())
        self.assertEqual(updated_metadata.label, str(target.resolve()))


if __name__ == "__main__":
    unittest.main()
