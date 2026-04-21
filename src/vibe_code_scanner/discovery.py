"""Repository discovery and file filtering."""

from __future__ import annotations

import codecs
import fnmatch
import os
from pathlib import Path
from pathlib import PurePosixPath

from .defaults import DEFAULT_BINARY_SAMPLE_SIZE, LANGUAGE_HINTS
from .models import AppConfig, SkippedPath, SourceFile


def discover_source_files(config: AppConfig) -> tuple[list[SourceFile], list[SkippedPath]]:
    files: list[SourceFile] = []
    skipped: list[SkippedPath] = []
    ignored_directory_names = {name.lower() for name in config.ignored_directories}

    for dirpath, dirnames, filenames in os.walk(config.root_path, topdown=True, followlinks=False):
        current_dir = Path(dirpath)
        kept_dirs: list[str] = []

        for dirname in dirnames:
            full_dir = current_dir / dirname
            rel_dir = _to_relative_posix(config.root_path, full_dir)
            if full_dir.is_symlink():
                skipped.append(SkippedPath(relative_path=rel_dir, reason="symlinked_directory"))
                continue
            if dirname.lower() in ignored_directory_names:
                skipped.append(SkippedPath(relative_path=rel_dir, reason="ignored_directory"))
                continue
            kept_dirs.append(dirname)
        dirnames[:] = kept_dirs

        for filename in filenames:
            full_path = current_dir / filename
            rel_path = _to_relative_posix(config.root_path, full_path)

            if full_path.is_symlink():
                skipped.append(SkippedPath(relative_path=rel_path, reason="symlinked_file"))
                continue
            if not _matches_any(rel_path, config.include_globs):
                skipped.append(SkippedPath(relative_path=rel_path, reason="not_included"))
                continue
            if _matches_any(rel_path, config.exclude_globs):
                skipped.append(SkippedPath(relative_path=rel_path, reason="excluded_pattern"))
                continue
            try:
                size_bytes = full_path.stat().st_size
            except OSError:
                skipped.append(SkippedPath(relative_path=rel_path, reason="stat_failed"))
                continue
            if size_bytes > config.max_file_size_bytes:
                skipped.append(SkippedPath(relative_path=rel_path, reason="too_large"))
                continue
            if is_binary_file(full_path):
                skipped.append(SkippedPath(relative_path=rel_path, reason="binary_file"))
                continue

            files.append(
                SourceFile(
                    root_path=config.root_path,
                    path=full_path,
                    relative_path=rel_path,
                    size_bytes=size_bytes,
                    language_hint=detect_language_hint(full_path),
                )
            )

    files.sort(key=lambda item: item.relative_path)
    skipped.sort(key=lambda item: item.relative_path)
    return files, skipped


def read_text_file(source_file: SourceFile) -> str:
    data = source_file.path.read_bytes()
    if data.startswith(codecs.BOM_UTF16_BE) or data.startswith(codecs.BOM_UTF16_LE):
        return data.decode("utf-16")
    for encoding in ("utf-8-sig", "utf-8"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def is_binary_file(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            sample = handle.read(DEFAULT_BINARY_SAMPLE_SIZE)
    except OSError:
        return True
    if not sample:
        return False
    if b"\x00" in sample:
        return True

    text_bytes = bytearray({7, 8, 9, 10, 12, 13, 27})
    text_bytes.extend(range(0x20, 0x100))
    translated = sample.translate(None, bytes(text_bytes))
    return len(translated) / len(sample) > 0.30


def detect_language_hint(path: Path) -> str:
    if path.name == "Dockerfile":
        return "dockerfile"
    return LANGUAGE_HINTS.get(path.suffix.lower(), "text")


def _matches_any(relative_path: str, patterns: list[str]) -> bool:
    if not patterns:
        return False
    name = Path(relative_path).name
    relative_posix = PurePosixPath(relative_path)
    for pattern in patterns:
        normalized_pattern = pattern.replace("\\", "/")
        basename_pattern = normalized_pattern[3:] if normalized_pattern.startswith("**/") else normalized_pattern
        if (
            relative_posix.match(normalized_pattern)
            or fnmatch.fnmatch(relative_path, normalized_pattern)
            or fnmatch.fnmatch(name, basename_pattern)
        ):
            return True
    return False


def _to_relative_posix(root_path: Path, target: Path) -> str:
    return target.relative_to(root_path).as_posix()
