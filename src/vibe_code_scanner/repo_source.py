"""Helpers for acquiring a public GitHub repository for scanning."""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


class RepoAcquisitionError(RuntimeError):
    """Raised when a requested repository cannot be acquired."""


@dataclass(slots=True)
class AcquiredRepository:
    repo_url: str
    normalized_repo_url: str
    checkout_path: Path
    requested_ref: str | None
    checked_out_ref: str | None


_GITHUB_REPO_PATTERN = re.compile(
    r"^https://github\.com/(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+?)(?:\.git)?/?$"
)


def acquire_github_repo(repo_url: str, destination_root: Path, ref: str | None = None) -> AcquiredRepository:
    normalized_url = normalize_github_repo_url(repo_url)
    git_executable = shutil.which("git")
    if not git_executable:
        raise RepoAcquisitionError(
            "git is required to scan a GitHub repository, but it was not found on PATH."
        )

    repo_name = normalized_url.rstrip("/").split("/")[-1].removesuffix(".git")
    checkout_path = destination_root / repo_name
    clone_command = [git_executable, "clone", "--depth", "1"]
    if ref:
        clone_command.extend(["--branch", ref])
    clone_command.extend([normalized_url, str(checkout_path)])

    clone_result = subprocess.run(
        clone_command,
        capture_output=True,
        text=True,
        check=False,
    )
    if clone_result.returncode != 0:
        error_message = clone_result.stderr.strip() or clone_result.stdout.strip() or "git clone failed."
        raise RepoAcquisitionError(f"Failed to clone {normalized_url}: {error_message}")

    checked_out_ref = resolve_checked_out_ref(git_executable, checkout_path)
    return AcquiredRepository(
        repo_url=repo_url,
        normalized_repo_url=normalized_url,
        checkout_path=checkout_path,
        requested_ref=ref,
        checked_out_ref=checked_out_ref,
    )


def normalize_github_repo_url(repo_url: str) -> str:
    normalized = repo_url.strip()
    match = _GITHUB_REPO_PATTERN.fullmatch(normalized)
    if not match:
        raise RepoAcquisitionError(
            "Invalid GitHub repository URL. Use a public https://github.com/<owner>/<repo> URL."
        )
    owner = match.group("owner")
    repo = match.group("repo")
    return f"https://github.com/{owner}/{repo}.git"


def resolve_checked_out_ref(git_executable: str, checkout_path: Path) -> str | None:
    branch_result = subprocess.run(
        [git_executable, "-C", str(checkout_path), "rev-parse", "--abbrev-ref", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    if branch_result.returncode == 0:
        branch = branch_result.stdout.strip()
        if branch and branch != "HEAD":
            return branch

    tag_result = subprocess.run(
        [git_executable, "-C", str(checkout_path), "describe", "--tags", "--exact-match"],
        capture_output=True,
        text=True,
        check=False,
    )
    if tag_result.returncode == 0:
        tag = tag_result.stdout.strip()
        if tag:
            return tag

    commit_result = subprocess.run(
        [git_executable, "-C", str(checkout_path), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=False,
    )
    if commit_result.returncode == 0:
        commit = commit_result.stdout.strip()
        return commit or None
    return None
