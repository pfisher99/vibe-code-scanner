from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vibe_code_scanner.models import ApiStyle, AppConfig, ScanMode, SearchBackend, SourceFile
from vibe_code_scanner.research import DependencyResearcher


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
        include_globs=["**/*.py", "**/*.json", "**/*.toml", "**/requirements.txt"],
        exclude_globs=[],
        ignored_directories=[],
        research_enabled=True,
        search_backend=SearchBackend.SEARXNG,
        search_base_url="http://search.local",
        research_max_results=2,
    )


class ResearchTests(unittest.TestCase):
    def test_dependency_researcher_extracts_versions_vulns_and_search_results(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            package_json = root / "package.json"
            package_json.write_text(
                '{"dependencies":{"express":"4.18.2"},"devDependencies":{"eslint":"^9.0.0"}}',
                encoding="utf-8",
            )
            requirements_txt = root / "requirements.txt"
            requirements_txt.write_text("requests==2.31.0\nflask>=3.0\n", encoding="utf-8")
            pyproject = root / "pyproject.toml"
            pyproject.write_text(
                """
[project]
dependencies = ["httpx==0.27.0"]

[tool.poetry.dependencies]
python = "^3.11"
fastapi = "0.115.0"
""".strip(),
                encoding="utf-8",
            )
            source_files = [
                SourceFile(root, package_json, "package.json", package_json.stat().st_size, "json"),
                SourceFile(root, requirements_txt, "requirements.txt", requirements_txt.stat().st_size, "text"),
                SourceFile(root, pyproject, "pyproject.toml", pyproject.stat().st_size, "toml"),
            ]

            def fake_fetch_json(self, url: str):
                if "registry.npmjs.org" in url:
                    return {"dist-tags": {"latest": "5.1.0"}}
                if "pypi.org" in url:
                    package_name = url.split("/")[-2]
                    return {"info": {"version": f"{package_name}-latest"}}
                if "search.local" in url:
                    return {
                        "results": [
                            {"title": "Advisory", "url": "https://example.com/advisory", "content": "snippet"}
                        ]
                    }
                raise AssertionError(f"Unexpected URL: {url}")

            def fake_post_json(self, url: str, payload: dict):
                if payload["package"]["name"] == "express":
                    return {
                        "vulns": [
                            {
                                "id": "GHSA-test-1234",
                                "summary": "Known vuln",
                                "aliases": ["CVE-2024-0001"],
                                "severity": [{"type": "CVSS_V3", "score": "HIGH"}],
                                "references": [{"type": "ADVISORY", "url": "https://osv.dev/vuln/123"}],
                            }
                        ]
                    }
                return {"vulns": []}

            with patch.object(DependencyResearcher, "_fetch_json", new=fake_fetch_json), patch.object(
                DependencyResearcher, "_post_json", new=fake_post_json
            ):
                summary = DependencyResearcher(make_config(root)).run(source_files)

        self.assertEqual(summary.total_dependencies, 6)
        self.assertEqual(summary.vulnerable_dependencies, 1)
        express = next(item for item in summary.dependencies if item.name == "express")
        self.assertEqual(express.latest_version, "5.1.0")
        self.assertEqual(express.vulnerabilities[0].id, "GHSA-test-1234")
        self.assertEqual(len(express.search_results), 1)
        flask = next(item for item in summary.dependencies if item.name == "flask")
        self.assertIsNone(flask.resolved_version)


if __name__ == "__main__":
    unittest.main()
