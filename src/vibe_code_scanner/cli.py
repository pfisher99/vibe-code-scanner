"""CLI entrypoint for vibe-code-scanner."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
import tempfile
from contextlib import nullcontext
from pathlib import Path

from .config import ConfigError, load_app_config
from .models import ScanSourceKind, ScanSourceMetadata
from .repo_source import RepoAcquisitionError, acquire_github_repo
from .scanner import RepositoryScanner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Scan a repository with a local AI model.")
    parser.add_argument("root", nargs="?", help="Repository root to scan. Overrides config root_path.")
    parser.add_argument("--repo", help="Public GitHub repository URL to clone and scan.")
    parser.add_argument("--ref", help="Optional branch or tag to check out when using --repo.")
    parser.add_argument("--config", help="Path to a TOML config file.")
    parser.add_argument("--output", help="Export directory override.")
    parser.add_argument("--base-url", help="OpenAI-compatible endpoint root override.")
    parser.add_argument("--model", help="Model name override.")
    parser.add_argument(
        "--trace",
        action="store_true",
        default=None,
        help="Persist per-chunk prompt metadata in raw artifacts.",
    )
    parser.add_argument(
        "--research",
        action="store_true",
        default=None,
        help="Run a final LLM-guided research pass over the completed scan outputs.",
    )
    parser.add_argument(
        "--search-backend",
        choices=["none", "searxng", "duckduckgo"],
        help="Optional search backend available to the final research pass.",
    )
    parser.add_argument(
        "--search-base-url",
        help="Base URL for the configured search backend, for example http://127.0.0.1:8080.",
    )
    parser.add_argument(
        "--scan-mode",
        choices=["security", "security_and_quality"],
        help="Scan mode override.",
    )
    parser.add_argument(
        "--api-style",
        choices=["chat_completions", "responses"],
        help="API style override.",
    )
    parser.add_argument(
        "--max-concurrency",
        type=int,
        help="Maximum concurrent requests override.",
    )
    parser.add_argument(
        "--max-files",
        type=int,
        help="Testing helper: scan only a random subset of this many eligible files.",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="CLI log verbosity.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.root and args.repo:
        parser.error("Provide either a local root path or --repo, not both.")
    if args.ref and not args.repo:
        parser.error("--ref can only be used together with --repo.")

    _configure_logging(args.log_level)

    config_path = Path(args.config).expanduser() if args.config else _default_config_path()
    temp_repo_context = tempfile.TemporaryDirectory(prefix="vibe-code-scanner-") if args.repo else nullcontext()

    try:
        with temp_repo_context as temp_repo_dir:
            root_override, source_metadata = _resolve_scan_source(args, Path(temp_repo_dir) if temp_repo_dir else None)
            overrides = {
                "root_path": root_override,
                "export_dir": str(Path(args.output).expanduser().resolve()) if args.output else None,
                "base_url": args.base_url,
                "model_name": args.model,
                "trace": args.trace,
                "research": args.research,
                "search_backend": args.search_backend,
                "search_base_url": args.search_base_url,
                "scan_mode": args.scan_mode,
                "api_style": args.api_style,
                "max_concurrent_requests": args.max_concurrency,
                "max_files": args.max_files,
            }

            try:
                config = load_app_config(config_path, overrides)
            except ConfigError as exc:
                print(f"Configuration error: {exc}", file=sys.stderr)
                return 2

            try:
                summary = asyncio.run(RepositoryScanner(config, source_metadata=source_metadata).run())
            except KeyboardInterrupt:
                print("Scan cancelled.", file=sys.stderr)
                return 130
    except RepoAcquisitionError as exc:
        print(f"Repository error: {exc}", file=sys.stderr)
        return 2

    print(f"Scan finished: {summary.run_dir}")
    print(f"Source: {summary.source_kind} ({summary.source_label})")
    print(
        "Files scanned: "
        f"{summary.total_files_scanned}, chunks sent: {summary.total_chunks_sent}, "
        f"errors: {len(summary.errors)}"
    )
    return 0


def _default_config_path() -> Path | None:
    candidate = Path("scanner.toml")
    return candidate if candidate.exists() else None


def _resolve_scan_source(args: argparse.Namespace, temp_repo_dir: Path | None) -> tuple[str | None, ScanSourceMetadata]:
    if args.repo:
        if temp_repo_dir is None:
            raise RepoAcquisitionError("A temporary working directory was not created for the repository clone.")
        acquired_repo = acquire_github_repo(args.repo, temp_repo_dir, ref=args.ref)
        return (
            str(acquired_repo.checkout_path.resolve()),
            ScanSourceMetadata(
                kind=ScanSourceKind.GITHUB_REPO,
                label=acquired_repo.normalized_repo_url,
                repo_url=acquired_repo.normalized_repo_url,
                requested_ref=acquired_repo.requested_ref,
                checked_out_ref=acquired_repo.checked_out_ref,
            ),
        )

    root_path = str(Path(args.root).expanduser().resolve()) if args.root else None
    label = root_path or "config root_path"
    return root_path, ScanSourceMetadata(kind=ScanSourceKind.LOCAL_PATH, label=label)


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level),
        format="%(levelname)s %(name)s: %(message)s",
    )


if __name__ == "__main__":
    raise SystemExit(main())
