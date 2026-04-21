from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from vibe_code_scanner.repo_source import RepoAcquisitionError, acquire_github_repo, normalize_github_repo_url


class RepoSourceTests(unittest.TestCase):
    def test_normalize_github_repo_url_accepts_plain_and_git_urls(self) -> None:
        self.assertEqual(
            normalize_github_repo_url("https://github.com/OWASP/NodeGoat"),
            "https://github.com/OWASP/NodeGoat.git",
        )
        self.assertEqual(
            normalize_github_repo_url("https://github.com/owasp/NodeGoat.git"),
            "https://github.com/owasp/NodeGoat.git",
        )

    def test_normalize_github_repo_url_rejects_invalid_urls(self) -> None:
        with self.assertRaises(RepoAcquisitionError):
            normalize_github_repo_url("https://gitlab.com/owasp/NodeGoat")

    def test_acquire_github_repo_uses_git_clone_and_resolves_ref(self) -> None:
        commands: list[list[str]] = []

        def fake_run(command, capture_output, text, check):
            commands.append(command)
            rendered = " ".join(command)
            if "clone" in command:
                return _CompletedProcess(0, "", "")
            if "--abbrev-ref HEAD" in rendered:
                return _CompletedProcess(0, "main\n", "")
            raise AssertionError(f"Unexpected command: {command}")

        with tempfile.TemporaryDirectory() as temp_dir, patch(
            "vibe_code_scanner.repo_source.shutil.which",
            return_value="git",
        ), patch(
            "vibe_code_scanner.repo_source.subprocess.run",
            side_effect=fake_run,
        ):
            acquired = acquire_github_repo(
                "https://github.com/OWASP/NodeGoat",
                Path(temp_dir),
                ref="main",
            )

        self.assertEqual(acquired.normalized_repo_url, "https://github.com/OWASP/NodeGoat.git")
        self.assertEqual(acquired.requested_ref, "main")
        self.assertEqual(acquired.checked_out_ref, "main")
        self.assertEqual(commands[0][:5], ["git", "clone", "--depth", "1", "--branch"])
        self.assertTrue(str(acquired.checkout_path).endswith("NodeGoat"))

    def test_acquire_github_repo_fails_when_git_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch(
            "vibe_code_scanner.repo_source.shutil.which",
            return_value=None,
        ):
            with self.assertRaises(RepoAcquisitionError):
                acquire_github_repo("https://github.com/OWASP/NodeGoat", Path(temp_dir))


class _CompletedProcess:
    def __init__(self, returncode: int, stdout: str, stderr: str) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


if __name__ == "__main__":
    unittest.main()
