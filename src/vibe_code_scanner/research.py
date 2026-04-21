"""Optional dependency/security enrichment for scan runs."""

from __future__ import annotations

import json
import re
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from .discovery import read_text_file
from .models import (
    AppConfig,
    DependencyResearchItem,
    DependencyVulnerability,
    ResearchReference,
    ResearchSummary,
    SearchBackend,
    SourceFile,
)

EXACT_VERSION_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
PYTHON_REQUIREMENT_PATTERN = re.compile(r"^\s*([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*([<>=!~]{1,2}\s*[^;,\s]+)?")


class ResearchError(RuntimeError):
    """Raised when external research data cannot be fetched."""


class DependencyResearcher:
    def __init__(self, config: AppConfig) -> None:
        self._config = config

    def run(self, source_files: list[SourceFile]) -> ResearchSummary:
        dependencies = self._extract_dependencies(source_files)
        errors: list[str] = []

        for dependency in dependencies:
            try:
                dependency.latest_version = self._lookup_latest_version(dependency)
            except ResearchError as exc:
                dependency.errors.append(str(exc))
                errors.append(str(exc))

            if dependency.resolved_version:
                try:
                    dependency.vulnerabilities = self._lookup_vulnerabilities(dependency)
                except ResearchError as exc:
                    dependency.errors.append(str(exc))
                    errors.append(str(exc))

            if (
                self._config.search_backend != SearchBackend.NONE
                and self._config.search_base_url
                and dependency.vulnerabilities
            ):
                try:
                    dependency.search_results = self._search_dependency_context(dependency)
                except ResearchError as exc:
                    dependency.errors.append(str(exc))
                    errors.append(str(exc))

        vulnerable_dependencies = sum(1 for item in dependencies if item.vulnerabilities)
        searched_dependencies = sum(1 for item in dependencies if item.search_results)
        return ResearchSummary(
            dependencies=dependencies,
            total_dependencies=len(dependencies),
            vulnerable_dependencies=vulnerable_dependencies,
            searched_dependencies=searched_dependencies,
            errors=errors,
        )

    def _extract_dependencies(self, source_files: list[SourceFile]) -> list[DependencyResearchItem]:
        items: list[DependencyResearchItem] = []
        seen: set[tuple[str, str, str, str | None]] = set()

        for source_file in source_files:
            path = Path(source_file.relative_path)
            name = path.name.lower()
            try:
                text = read_text_file(source_file)
            except OSError:
                continue

            extracted: list[DependencyResearchItem] = []
            if name == "package.json":
                extracted = self._from_package_json(source_file.relative_path, text)
            elif name == "requirements.txt" or name.startswith("requirements-") and name.endswith(".txt"):
                extracted = self._from_requirements_txt(source_file.relative_path, text)
            elif name == "pyproject.toml":
                extracted = self._from_pyproject_toml(source_file.relative_path, text)

            for item in extracted:
                key = (item.source_file, item.ecosystem, item.name, item.version_spec)
                if key in seen:
                    continue
                seen.add(key)
                items.append(item)

        items.sort(key=lambda item: (item.source_file, item.ecosystem, item.name))
        return items

    def _from_package_json(self, relative_path: str, text: str) -> list[DependencyResearchItem]:
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return []
        if not isinstance(payload, dict):
            return []

        items: list[DependencyResearchItem] = []
        for section_name in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            section = payload.get(section_name)
            if not isinstance(section, dict):
                continue
            for name, spec in section.items():
                if not isinstance(spec, str):
                    continue
                spec = spec.strip()
                items.append(
                    DependencyResearchItem(
                        source_file=relative_path,
                        ecosystem="npm",
                        name=name,
                        version_spec=spec,
                        resolved_version=_extract_exact_version("npm", spec),
                        latest_version=None,
                    )
                )
        return items

    def _from_requirements_txt(self, relative_path: str, text: str) -> list[DependencyResearchItem]:
        items: list[DependencyResearchItem] = []
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("-r") or line.startswith("--"):
                continue
            line = line.split("#", 1)[0].strip()
            match = PYTHON_REQUIREMENT_PATTERN.match(line)
            if not match:
                continue
            name = match.group(1)
            operator_and_version = (match.group(2) or "").replace(" ", "")
            version_spec = operator_and_version or None
            items.append(
                DependencyResearchItem(
                    source_file=relative_path,
                    ecosystem="PyPI",
                    name=name,
                    version_spec=version_spec,
                    resolved_version=_extract_exact_version("PyPI", version_spec),
                    latest_version=None,
                )
            )
        return items

    def _from_pyproject_toml(self, relative_path: str, text: str) -> list[DependencyResearchItem]:
        try:
            payload = tomllib.loads(text)
        except tomllib.TOMLDecodeError:
            return []

        items: list[DependencyResearchItem] = []
        project = payload.get("project")
        if isinstance(project, dict):
            dependencies = project.get("dependencies", [])
            if isinstance(dependencies, list):
                for entry in dependencies:
                    if not isinstance(entry, str):
                        continue
                    item = _parse_python_dependency_string(relative_path, entry)
                    if item is not None:
                        items.append(item)

        poetry_deps = payload.get("tool", {}).get("poetry", {}).get("dependencies", {})
        if isinstance(poetry_deps, dict):
            for name, spec in poetry_deps.items():
                if name.lower() == "python":
                    continue
                version_spec = _normalize_poetry_spec(spec)
                items.append(
                    DependencyResearchItem(
                        source_file=relative_path,
                        ecosystem="PyPI",
                        name=name,
                        version_spec=version_spec,
                        resolved_version=_extract_exact_version("PyPI", version_spec),
                        latest_version=None,
                    )
                )
        return items

    def _lookup_latest_version(self, dependency: DependencyResearchItem) -> str | None:
        if dependency.ecosystem == "npm":
            package_name = urllib.parse.quote(dependency.name, safe="@/")
            payload = self._fetch_json(f"https://registry.npmjs.org/{package_name}")
            dist_tags = payload.get("dist-tags", {})
            latest = dist_tags.get("latest")
            return latest if isinstance(latest, str) else None

        if dependency.ecosystem == "PyPI":
            package_name = urllib.parse.quote(dependency.name, safe="")
            payload = self._fetch_json(f"https://pypi.org/pypi/{package_name}/json")
            info = payload.get("info", {})
            latest = info.get("version")
            return latest if isinstance(latest, str) else None

        return None

    def _lookup_vulnerabilities(self, dependency: DependencyResearchItem) -> list[DependencyVulnerability]:
        osv_ecosystem = "npm" if dependency.ecosystem == "npm" else dependency.ecosystem
        payload = self._post_json(
            "https://api.osv.dev/v1/query",
            {
                "package": {"ecosystem": osv_ecosystem, "name": dependency.name},
                "version": dependency.resolved_version,
            },
        )
        vulns = payload.get("vulns", [])
        if not isinstance(vulns, list):
            return []

        results: list[DependencyVulnerability] = []
        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue
            references = []
            for reference in vuln.get("references", []):
                if not isinstance(reference, dict):
                    continue
                url = reference.get("url")
                if isinstance(url, str) and url:
                    references.append(
                        ResearchReference(
                            title=str(reference.get("type", "reference")).replace("_", " ").title(),
                            url=url,
                            snippet="",
                        )
                    )
            aliases = [alias for alias in vuln.get("aliases", []) if isinstance(alias, str)]
            results.append(
                DependencyVulnerability(
                    id=str(vuln.get("id", "unknown")),
                    summary=str(vuln.get("summary", "")).strip() or str(vuln.get("details", "")).strip(),
                    aliases=aliases,
                    severity=_extract_osv_severity(vuln),
                    references=references[: self._config.research_max_results],
                )
            )
        return results

    def _search_dependency_context(self, dependency: DependencyResearchItem) -> list[ResearchReference]:
        query = f"{dependency.name} {dependency.vulnerabilities[0].id} advisory"
        payload = self._fetch_json(
            f"{self._config.search_base_url.rstrip('/')}/search?"
            + urllib.parse.urlencode({"q": query, "format": "json"})
        )
        results = payload.get("results", [])
        if not isinstance(results, list):
            return []

        references: list[ResearchReference] = []
        for result in results[: self._config.research_max_results]:
            if not isinstance(result, dict):
                continue
            url = result.get("url")
            if not isinstance(url, str) or not url:
                continue
            references.append(
                ResearchReference(
                    title=str(result.get("title", "Search Result")).strip() or "Search Result",
                    url=url,
                    snippet=str(result.get("content", "")).strip(),
                )
            )
        return references

    def _fetch_json(self, url: str) -> dict[str, Any]:
        request = urllib.request.Request(url, headers={"Accept": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=self._config.request_timeout_seconds) as response:
                charset = response.headers.get_content_charset("utf-8")
                text = response.read().decode(charset)
        except urllib.error.HTTPError as exc:
            raise ResearchError(f"GET {url} failed with HTTP {exc.code}.") from exc
        except urllib.error.URLError as exc:
            raise ResearchError(f"Could not reach research endpoint {url}: {exc.reason}") from exc

        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ResearchError(f"Research endpoint returned invalid JSON for {url}.") from exc
        if not isinstance(payload, dict):
            raise ResearchError(f"Research endpoint returned an unexpected payload for {url}.")
        return payload

    def _post_json(self, url: str, payload: dict[str, Any]) -> dict[str, Any]:
        request = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self._config.request_timeout_seconds) as response:
                charset = response.headers.get_content_charset("utf-8")
                text = response.read().decode(charset)
        except urllib.error.HTTPError as exc:
            raise ResearchError(f"POST {url} failed with HTTP {exc.code}.") from exc
        except urllib.error.URLError as exc:
            raise ResearchError(f"Could not reach research endpoint {url}: {exc.reason}") from exc

        try:
            payload_json = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ResearchError(f"Research endpoint returned invalid JSON for {url}.") from exc
        if not isinstance(payload_json, dict):
            raise ResearchError(f"Research endpoint returned an unexpected payload for {url}.")
        return payload_json


def _parse_python_dependency_string(relative_path: str, entry: str) -> DependencyResearchItem | None:
    entry = entry.strip()
    if not entry:
        return None
    match = PYTHON_REQUIREMENT_PATTERN.match(entry)
    if not match:
        return None
    name = match.group(1)
    operator_and_version = (match.group(2) or "").replace(" ", "")
    version_spec = operator_and_version or None
    return DependencyResearchItem(
        source_file=relative_path,
        ecosystem="PyPI",
        name=name,
        version_spec=version_spec,
        resolved_version=_extract_exact_version("PyPI", version_spec),
        latest_version=None,
    )


def _normalize_poetry_spec(spec: Any) -> str | None:
    if isinstance(spec, str):
        normalized = spec.strip()
        return normalized or None
    if isinstance(spec, dict):
        version = spec.get("version")
        if isinstance(version, str):
            normalized = version.strip()
            return normalized or None
    return None


def _extract_exact_version(ecosystem: str, version_spec: str | None) -> str | None:
    if not version_spec:
        return None
    normalized = version_spec.strip()
    if normalized.startswith("=="):
        normalized = normalized[2:]
    elif normalized.startswith("="):
        normalized = normalized[1:]
    elif any(token in normalized for token in ("^", "~", ">", "<", "!", "*", ",", "||", " ", "[")):
        return None
    normalized = normalized.strip().strip('"').strip("'")
    if not normalized or not EXACT_VERSION_PATTERN.fullmatch(normalized):
        return None
    return normalized


def _extract_osv_severity(vuln: dict[str, Any]) -> str | None:
    severity = vuln.get("severity", [])
    if isinstance(severity, list) and severity:
        first = severity[0]
        if isinstance(first, dict):
            score = first.get("score")
            if isinstance(score, str):
                return score
    database_specific = vuln.get("database_specific", {})
    severity_value = database_specific.get("severity")
    return severity_value if isinstance(severity_value, str) else None
