"""Post-scan research agent for final deep analysis."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from html.parser import HTMLParser
import json
import re
import textwrap
import urllib.error
import urllib.parse
import urllib.request
from html import unescape
from importlib import resources
from typing import Any

from .chunking import chunk_text
from .client import ModelClientError, OpenAICompatibleClient
from .models import (
    AppConfig,
    FileScanResult,
    ResearchReference,
    ResearchSummary,
    ResearchToolCall,
    ScanSourceMetadata,
    SearchBackend,
)
from .parser import ResponseParseError, load_json_object
from .tokenization import build_token_counter

MAX_RESEARCH_STEPS = 8
MAX_FILE_REPORT_CHARS = 12_000
MAX_FETCH_CONTENT_CHARS = 12_000
MAX_RECOMMENDED_FILES = 3
MAX_RECOMMENDED_SEARCH_QUERIES = 5
MIN_FILE_REPORTS_BEFORE_FINISH = 2
MIN_WEB_SEARCHES_BEFORE_FINISH = 1
MIN_FETCHES_BEFORE_FINISH = 1
TAG_PATTERN = re.compile(r"(?is)<[^>]+>")
SCRIPT_STYLE_PATTERN = re.compile(r"(?is)<(script|style).*?>.*?</\1>")
WHITESPACE_PATTERN = re.compile(r"\s+")
QUOTED_DEPENDENCY_PATTERN = re.compile(r'"([^"]+)"')


class ResearchError(RuntimeError):
    """Raised when post-scan research cannot proceed cleanly."""


class PostScanResearcher:
    def __init__(self, config: AppConfig) -> None:
        self._config = config
        self._token_counter = build_token_counter(config)

    async def run(
        self,
        client: OpenAICompatibleClient,
        file_results: list[FileScanResult],
        source_metadata: ScanSourceMetadata,
    ) -> ResearchSummary:
        if not any(result.findings for result in file_results):
            return ResearchSummary(
                report_markdown="# Final Research Report\n\nNo findings were available for post-scan research.\n"
            )

        messages = [
            {"role": "system", "content": _load_research_system_prompt()},
            {"role": "user", "content": self._initial_brief(file_results, source_metadata)},
        ]
        references_by_url: dict[str, ResearchReference] = {}
        files_consulted: set[str] = set()
        search_queries: list[str] = []
        tool_calls: list[ResearchToolCall] = []
        errors: list[str] = []
        listed_findings = False
        successful_searches = 0
        fetched_urls: set[str] = set()

        for step in range(1, MAX_RESEARCH_STEPS + 1):
            trace_label = f"research step {step}/{MAX_RESEARCH_STEPS}"
            try:
                response_text, _raw_payload, _trace = await client.analyze_messages(
                    messages,
                    max_tokens_per_request=self._config.effective_research_max_tokens_per_request(),
                    thinking_token_budget=self._config.effective_research_thinking_token_budget(),
                )
            except ModelClientError as exc:
                errors.append(f"Research step {step} failed: {exc}")
                break

            try:
                action = _parse_action_response(response_text)
            except ResearchError as exc:
                errors.append(
                    "Research step "
                    f"{step} returned invalid JSON action: {exc}. "
                    f"Response excerpt: {_truncate(response_text, 320)}"
                )
                break

            corrective_feedback = self._pre_action_feedback(
                action,
                file_results,
                listed_findings=listed_findings,
                files_consulted=files_consulted,
                references_by_url=references_by_url,
                successful_searches=successful_searches,
                fetched_urls=fetched_urls,
            )
            if corrective_feedback is not None:
                messages.append({"role": "assistant", "content": response_text})
                messages.append({"role": "user", "content": corrective_feedback})
                continue

            if action["action"] == "finish":
                report_markdown = str(action.get("report_markdown", "")).strip()
                if not report_markdown:
                    errors.append("Research finish action did not include report_markdown.")
                    break
                return ResearchSummary(
                    report_markdown=report_markdown,
                    tool_calls=tool_calls,
                    references=list(references_by_url.values()),
                    files_consulted=sorted(files_consulted),
                    search_queries=search_queries,
                    errors=errors,
                )

            tool_result, tool_argument, new_references, consulted_file, search_query = await self._execute_action(
                action,
                file_results,
            )
            if consulted_file is not None:
                files_consulted.add(consulted_file)
            if search_query is not None:
                search_queries.append(search_query)
                if "error" not in tool_result:
                    successful_searches += 1
            for reference in new_references:
                references_by_url[reference.url] = reference
            if action["action"] == "list_findings" and "error" not in tool_result:
                listed_findings = True
            if action["action"] == "fetch_url" and "error" not in tool_result:
                fetched_url = str(tool_result.get("url", "")).strip()
                if fetched_url:
                    fetched_urls.add(fetched_url)

            tool_calls.append(
                ResearchToolCall(
                    step=step,
                    action=action["action"],
                    argument=tool_argument,
                    result_preview=_truncate(json.dumps(tool_result, ensure_ascii=True), 320),
                    success="error" not in tool_result,
                )
            )
            messages.append({"role": "assistant", "content": response_text})
            messages.append(
                {
                    "role": "user",
                    "content": "Tool result:\n```json\n"
                    + json.dumps(tool_result, ensure_ascii=True, indent=2)
                    + "\n```",
                }
            )

        errors.append("Research loop ended before the model produced a final report.")
        return ResearchSummary(
            report_markdown=self._fallback_report(file_results, errors),
            tool_calls=tool_calls,
            references=list(references_by_url.values()),
            files_consulted=sorted(files_consulted),
            search_queries=search_queries,
            errors=errors,
        )

    def _initial_brief(self, file_results: list[FileScanResult], source_metadata: ScanSourceMetadata) -> str:
        total_findings = sum(len(result.findings) for result in file_results)
        findings_by_severity: dict[str, int] = {}
        file_lines: list[str] = []
        for result in sorted(file_results, key=lambda item: len(item.findings), reverse=True):
            if not result.findings:
                continue
            highlights = ", ".join(
                f"{finding.severity.value}:{finding.title}" for finding in result.findings[:3]
            )
            file_lines.append(
                f"- {result.source_file.relative_path}: {len(result.findings)} findings ({highlights})"
            )
            for finding in result.findings:
                findings_by_severity[finding.severity.value] = findings_by_severity.get(finding.severity.value, 0) + 1

        available_tools = [
            '- `list_findings`: list the scanner findings across files',
            '- `read_file_report`: read a specific per-file markdown report by relative file path, with optional `section_index` when paged',
            '- `fetch_url`: fetch and summarize a public URL, with optional `section_index` when paged',
        ]
        if self._search_is_available():
            available_tools.insert(2, '- `search_web`: search the web for public context')
        else:
            available_tools.insert(2, '- `search_web`: unavailable because no search backend is configured')

        severity_lines = "\n".join(
            f"- {severity}: {count}" for severity, count in sorted(findings_by_severity.items())
        ) or "- none"
        top_files_block = "\n".join(file_lines[:20]) or "- no files with findings"
        recommended_files = self._recommended_file_paths(file_results)
        recommended_queries = self._suggest_search_queries(file_results)
        recommended_files_block = (
            "\n".join(f"- {file_path}" for file_path in recommended_files) if recommended_files else "- none"
        )
        recommended_queries_block = (
            "\n".join(f"- {query}" for query in recommended_queries) if recommended_queries else "- none"
        )
        required_file_reports = min(
            MIN_FILE_REPORTS_BEFORE_FINISH,
            sum(1 for result in file_results if result.findings),
        )
        search_is_available = self._search_is_available()
        required_steps = [
            "1. Call `list_findings` first.",
            f"2. Read at least `{required_file_reports}` per-file report(s) for the highest-risk files before finishing.",
        ]
        if search_is_available:
            required_steps.append(
                "3. Because web search is available, perform at least one `search_web` lookup and `fetch_url` one authoritative result before finishing."
            )
            required_steps.append(
                "4. Prefer authoritative sources such as OWASP, NVD, vendor/framework docs, MDN, or official package advisories."
            )
        else:
            required_steps.append("3. Web search is unavailable in this run, so rely only on scanner outputs.")

        return f"""Completed scan source: {source_metadata.label}
Research goal: perform a final deep research pass over the scanner's own output.
The initial scan was completed without tools. In this phase you may inspect scan outputs and optionally use web tools before writing a final report.

Summary:
- Total files with findings: {sum(1 for result in file_results if result.findings)}
- Total findings: {total_findings}
- Findings by severity:
{severity_lines}

Top files:
{top_files_block}

Available tools:
{chr(10).join(available_tools)}

Required workflow:
{chr(10).join(f"- {step}" for step in required_steps)}

Recommended file reports:
{recommended_files_block}

Recommended search queries:
{recommended_queries_block}

Final report rules:
- Do not invent counts. If you mention totals or severity counts, copy them from tool results only.
- Call out which claims were externally validated and cite the URLs you actually fetched.
- Separate well-supported findings from uncertain or contextual ones.
- Make the final report useful to a human reviewer, not just a restatement of the raw findings.
- Tool results may be paged to stay within the request token budget. If a result says `truncated: true` and provides `next_section_index`, call the same tool again with that `section_index` if you need more context.
- Use web search to answer concrete questions: is this a real vulnerability pattern, what is the common impact, what is the official remediation, and for dependency issues what advisory or latest-version guidance exists.

When you are ready, return a `finish` action with a complete markdown report."""

    async def _execute_action(
        self,
        action: dict[str, Any],
        file_results: list[FileScanResult],
    ) -> tuple[dict[str, Any], str | None, list[ResearchReference], str | None, str | None]:
        action_name = action["action"]
        if action_name == "list_findings":
            return self._list_findings(file_results), None, [], None, None
        if action_name == "read_file_report":
            file_path = str(action.get("file_path", "")).strip()
            section_index = self._parse_section_index(action.get("section_index", 1))
            result = self._read_file_report(file_results, file_path, section_index=section_index)
            consulted_file = file_path if "error" not in result else None
            return result, file_path or None, [], consulted_file, None
        if action_name == "search_web":
            query = str(action.get("query", "")).strip()
            result = await self._search_web(query)
            references = [
                ResearchReference(
                    title=item.get("title", "Search Result"),
                    url=item.get("url", ""),
                    snippet=item.get("snippet", ""),
                )
                for item in result.get("results", [])
                if isinstance(item, dict) and isinstance(item.get("url"), str) and item.get("url")
            ]
            return result, query or None, references, None, query or None
        if action_name == "fetch_url":
            url = str(action.get("url", "")).strip()
            section_index = self._parse_section_index(action.get("section_index", 1))
            result = await self._fetch_url(url, section_index=section_index)
            references = []
            if isinstance(result.get("url"), str) and result.get("url"):
                references.append(
                    ResearchReference(
                        title=str(result.get("title", "Fetched URL")).strip() or "Fetched URL",
                        url=result["url"],
                        snippet=str(result.get("content_excerpt", "")).strip(),
                    )
                )
            return result, url or None, references, None, None
        return (
            {"error": f"Unsupported action '{action_name}'."},
            str(action.get("action", "")) or None,
            [],
            None,
            None,
        )

    def _list_findings(self, file_results: list[FileScanResult]) -> dict[str, Any]:
        files: list[dict[str, Any]] = []
        total_findings = 0
        severity_counts: dict[str, int] = {}
        for result in sorted(file_results, key=lambda item: len(item.findings), reverse=True):
            if not result.findings:
                continue
            total_findings += len(result.findings)
            for finding in result.findings:
                severity_counts[finding.severity.value] = severity_counts.get(finding.severity.value, 0) + 1
            files.append(
                {
                    "file_path": result.source_file.relative_path,
                    "finding_count": len(result.findings),
                    "findings": [
                        {
                            "title": finding.title,
                            "category": finding.category.value,
                            "severity": finding.severity.value,
                            "confidence": finding.confidence.value,
                            "lines": _format_line_range(finding.line_start, finding.line_end),
                            "evidence": _truncate(finding.evidence, 160),
                        }
                        for finding in result.findings[:5]
                    ],
                }
            )

        return {
            "total_files_with_findings": len(files),
            "total_findings": total_findings,
            "findings_by_severity": severity_counts,
            "files": files[:25],
            "suggested_file_reports": self._recommended_file_paths(file_results),
            "suggested_search_queries": self._suggest_search_queries(file_results),
        }

    def _read_file_report(
        self,
        file_results: list[FileScanResult],
        file_path: str,
        *,
        section_index: int = 1,
    ) -> dict[str, Any]:
        if not file_path:
            return {"error": "file_path is required for read_file_report."}
        for result in file_results:
            if result.source_file.relative_path == file_path:
                if result.report_path is None or not result.report_path.exists():
                    return {"error": f"Report for {file_path} was not generated."}
                report_text = result.report_path.read_text(encoding="utf-8")
                sections = self._paginate_text(report_text, self._tool_section_token_budget())
                if section_index > len(sections):
                    return {
                        "error": (
                            f"section_index {section_index} is out of range for {file_path};"
                            f" available sections: 1-{len(sections)}."
                        )
                    }
                return {
                    "file_path": file_path,
                    "section_index": section_index,
                    "total_sections": len(sections),
                    "report_markdown": _truncate(sections[section_index - 1], MAX_FILE_REPORT_CHARS),
                    "truncated": len(sections) > 1,
                    "next_section_index": (section_index + 1 if section_index < len(sections) else None),
                }
        return {"error": f"Unknown file path '{file_path}'."}

    async def _search_web(self, query: str) -> dict[str, Any]:
        if not query:
            return {"error": "query is required for search_web."}
        if self._config.search_backend == SearchBackend.NONE:
            return {"error": "search_web is unavailable because no search backend is configured."}
        try:
            return await asyncio.to_thread(self._search_web_sync, query)
        except ResearchError as exc:
            return {"query": query, "error": str(exc)}

    def _search_web_sync(self, query: str) -> dict[str, Any]:
        if self._config.search_backend == SearchBackend.DUCKDUCKGO:
            return self._search_duckduckgo_sync(query)
        payload = self._fetch_json(
            f"{self._config.search_base_url.rstrip('/')}/search?"
            + urllib.parse.urlencode({"q": query, "format": "json"})
        )
        results = payload.get("results", [])
        if not isinstance(results, list):
            return {"query": query, "results": []}
        normalized = []
        for result in results[: self._config.research_max_results]:
            if not isinstance(result, dict):
                continue
            url = result.get("url")
            if not isinstance(url, str) or not url:
                continue
            normalized.append(
                {
                    "title": str(result.get("title", "Search Result")).strip() or "Search Result",
                    "url": url,
                    "snippet": str(result.get("content", "")).strip(),
                }
            )
        return {"query": query, "results": normalized}

    def _search_duckduckgo_sync(self, query: str) -> dict[str, Any]:
        html = self._fetch_text(
            "https://html.duckduckgo.com/html/?"
            + urllib.parse.urlencode({"q": query}),
            accept="text/html,application/xhtml+xml",
        )
        parser = _DuckDuckGoHtmlParser()
        parser.feed(html)
        parser.close()
        normalized = []
        for result in parser.results[: self._config.research_max_results]:
            if not result.get("url"):
                continue
            normalized.append(
                {
                    "title": str(result.get("title", "Search Result")).strip() or "Search Result",
                    "url": str(result["url"]).strip(),
                    "snippet": str(result.get("snippet", "")).strip(),
                }
            )
        return {"query": query, "results": normalized}

    async def _fetch_url(self, url: str, *, section_index: int = 1) -> dict[str, Any]:
        if not url:
            return {"error": "url is required for fetch_url."}
        return await asyncio.to_thread(self._fetch_url_sync, url, section_index)

    def _fetch_url_sync(self, url: str, section_index: int = 1) -> dict[str, Any]:
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "text/html,application/xhtml+xml,application/xml,text/plain;q=0.9,*/*;q=0.8",
                "User-Agent": "vibe-code-scanner/0.1 research-agent",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self._config.request_timeout_seconds) as response:
                charset = response.headers.get_content_charset("utf-8")
                raw_text = response.read().decode(charset, errors="replace")
        except urllib.error.HTTPError as exc:
            return {"error": f"GET {url} failed with HTTP {exc.code}."}
        except urllib.error.URLError as exc:
            return {"error": f"Could not reach {url}: {exc.reason}"}

        title_match = re.search(r"(?is)<title[^>]*>(.*?)</title>", raw_text)
        title = _clean_html_text(title_match.group(1)) if title_match else url
        content_sections = self._paginate_text(
            _truncate(_clean_html_text(raw_text), MAX_FETCH_CONTENT_CHARS),
            self._tool_section_token_budget(),
        )
        if section_index > len(content_sections):
            return {
                "error": (
                    f"section_index {section_index} is out of range for {url};"
                    f" available sections: 1-{len(content_sections)}."
                )
            }
        content_excerpt = content_sections[section_index - 1]
        return {
            "url": url,
            "title": title or url,
            "section_index": section_index,
            "total_sections": len(content_sections),
            "content_excerpt": content_excerpt,
            "truncated": len(content_sections) > 1,
            "next_section_index": (section_index + 1 if section_index < len(content_sections) else None),
        }

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

    def _fetch_text(self, url: str, *, accept: str) -> str:
        request = urllib.request.Request(
            url,
            headers={
                "Accept": accept,
                "User-Agent": "vibe-code-scanner/0.1 research-agent",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self._config.request_timeout_seconds) as response:
                charset = response.headers.get_content_charset("utf-8")
                return response.read().decode(charset, errors="replace")
        except urllib.error.HTTPError as exc:
            raise ResearchError(f"GET {url} failed with HTTP {exc.code}.") from exc
        except urllib.error.URLError as exc:
            raise ResearchError(f"Could not reach research endpoint {url}: {exc.reason}") from exc

    def _fallback_report(self, file_results: list[FileScanResult], errors: list[str]) -> str:
        lines = [
            "# Final Research Report",
            "",
            "The post-scan research loop did not complete cleanly. Review the highest-priority findings below.",
            "",
            "## Highest Priority Findings",
            "",
        ]
        prioritized = sorted(
            [finding for result in file_results for finding in result.findings],
            key=lambda finding: (
                _severity_rank(finding.severity.value),
                _confidence_rank(finding.confidence.value),
            ),
        )
        if not prioritized:
            lines.append("No findings were available.")
        else:
            for finding in prioritized[:10]:
                lines.append(
                    f"- `{finding.severity.value}` {finding.file_path}:{_format_line_range(finding.line_start, finding.line_end)} - {finding.title}"
                )
        if errors:
            lines.extend(["", "## Errors", ""])
            lines.extend(f"- {error}" for error in errors)
        return "\n".join(lines).strip() + "\n"

    def _pre_action_feedback(
        self,
        action: dict[str, Any],
        file_results: list[FileScanResult],
        *,
        listed_findings: bool,
        files_consulted: set[str],
        references_by_url: dict[str, ResearchReference],
        successful_searches: int,
        fetched_urls: set[str],
    ) -> str | None:
        action_name = action["action"]
        if not listed_findings and action_name != "list_findings":
            return (
                "Do not skip the scanner overview. Call `list_findings` first so you have the exact counts,"
                " top files, and suggested next targets.\n"
                'Return JSON only, for example: {"action":"list_findings"}'
            )
        if action_name != "finish":
            return None

        required_file_reports = min(
            MIN_FILE_REPORTS_BEFORE_FINISH,
            sum(1 for result in file_results if result.findings),
        )
        if len(files_consulted) < required_file_reports:
            next_file = next(
                (file_path for file_path in self._recommended_file_paths(file_results) if file_path not in files_consulted),
                None,
            )
            if next_file is None:
                next_file = next(
                    (
                        result.source_file.relative_path
                        for result in file_results
                        if result.findings and result.source_file.relative_path not in files_consulted
                    ),
                    None,
                )
            example = (
                f'{{"action":"read_file_report","file_path":"{next_file}"}}'
                if next_file
                else '{"action":"read_file_report","file_path":"relative/path"}'
            )
            return (
                "Do not finish yet. Read more of the actual scanner outputs first."
                f" You have only consulted `{len(files_consulted)}` file report(s), and this run requires"
                f" at least `{required_file_reports}` before finishing.\n"
                f"Return JSON only, for example: {example}"
            )

        if self._search_is_available():
            if successful_searches < MIN_WEB_SEARCHES_BEFORE_FINISH:
                query = self._suggest_search_queries(file_results)[0] if self._suggest_search_queries(file_results) else "OWASP security guidance"
                return (
                    "Do not finish yet. Web search is available for this run, and you must perform at least"
                    " one external lookup before finishing.\n"
                    f'Return JSON only, for example: {{"action":"search_web","query":"{query}"}}'
                )
            if len(fetched_urls) < MIN_FETCHES_BEFORE_FINISH:
                candidate_url = next((url for url in references_by_url if url not in fetched_urls), None)
                if candidate_url:
                    return (
                        "Do not finish yet. Fetch at least one authoritative external reference before finishing"
                        " so the final report can cite concrete sources.\n"
                        f'Return JSON only, for example: {{"action":"fetch_url","url":"{candidate_url}"}}'
                    )
                query = self._suggest_search_queries(file_results)[0] if self._suggest_search_queries(file_results) else "OWASP security guidance"
                return (
                    "Do not finish yet. You still need one fetched external reference. Search first, then fetch"
                    " a promising authoritative result.\n"
                    f'Return JSON only, for example: {{"action":"search_web","query":"{query}"}}'
                )

        return None

    def _recommended_file_paths(self, file_results: list[FileScanResult]) -> list[str]:
        ranked = sorted(
            (result for result in file_results if result.findings),
            key=lambda item: (
                self._best_severity_rank(item),
                -len(item.findings),
                item.source_file.relative_path,
            ),
        )
        return [result.source_file.relative_path for result in ranked[:MAX_RECOMMENDED_FILES]]

    def _suggest_search_queries(self, file_results: list[FileScanResult]) -> list[str]:
        queries: list[str] = []
        ranked_findings = sorted(
            (finding for result in file_results for finding in result.findings),
            key=lambda finding: (
                _severity_rank(finding.severity.value),
                _confidence_rank(finding.confidence.value),
                finding.file_path,
            ),
        )
        for finding in ranked_findings:
            query = self._build_search_query(finding.title, finding.file_path, finding.evidence)
            if query and query not in queries:
                queries.append(query)
            if len(queries) >= MAX_RECOMMENDED_SEARCH_QUERIES:
                break
        return queries

    def _build_search_query(self, title: str, file_path: str, evidence: str) -> str:
        lowered_title = title.lower()
        lowered_evidence = evidence.lower()
        if "outdated " in lowered_title and file_path.endswith("package.json"):
            match = QUOTED_DEPENDENCY_PATTERN.search(evidence)
            if match:
                package_name = match.group(1).strip()
                if package_name:
                    return f"{package_name} security advisory latest version"
        keyword_queries = {
            "xss": "OWASP XSS prevention cheat sheet stored xss",
            "cross-site scripting": "OWASP XSS prevention cheat sheet stored xss",
            "xxe": "OWASP XXE prevention cheat sheet",
            "xml external entity": "OWASP XXE prevention cheat sheet",
            "command injection": "OWASP command injection prevention cheat sheet",
            "idor": "OWASP insecure direct object reference prevention cheat sheet",
            "direct object reference": "OWASP insecure direct object reference prevention cheat sheet",
            "deserialization": "OWASP insecure deserialization prevention cheat sheet",
            "csrf": "OWASP CSRF prevention cheat sheet",
            "open redirect": "OWASP unvalidated redirects forwards cheat sheet",
            "session secret": "express-session secret best practices official docs",
            "session": "OWASP session management cheat sheet express-session secret best practices",
            "authentication": "OWASP authentication cheat sheet express authentication best practices",
            "authorization": "OWASP authorization cheat sheet",
            "helmet": "helmet express security headers official docs",
            "content-security-policy": "MDN content security policy CSP security headers",
            "security headers": "OWASP secure headers project",
            "rate limiting": "express rate limiting authentication best practices",
            "logging": "OWASP logging cheat sheet sensitive data passwords",
            "autocomplete": "MDN autocomplete password input security guidance",
            "hardcoded password": "OWASP secrets management cheat sheet hardcoded credentials",
            "password": "OWASP logging cheat sheet sensitive data passwords",
        }
        for keyword, query in keyword_queries.items():
            if keyword in lowered_title or keyword in lowered_evidence:
                return query
        return f"{title} official security guidance"

    def _best_severity_rank(self, result: FileScanResult) -> int:
        return min((_severity_rank(finding.severity.value) for finding in result.findings), default=99)

    def _search_is_available(self) -> bool:
        if self._config.search_backend == SearchBackend.NONE:
            return False
        if self._config.search_backend == SearchBackend.SEARXNG:
            return bool(self._config.search_base_url)
        return True

    def _tool_section_token_budget(self) -> int:
        return max(1, (self._config.chunk_target_tokens * 3 // 4) // MAX_RESEARCH_STEPS)

    def _paginate_text(self, text: str, token_budget: int) -> list[str]:
        stripped = text.strip()
        if not stripped:
            return [""]
        wrapped_text = self._wrap_text_for_chunking(stripped)
        paging_config = replace(
            self._config,
            chunk_target_tokens=max(1, token_budget),
            chunk_overlap_tokens=0,
        )
        chunks = chunk_text(
            wrapped_text,
            paging_config,
            token_counter=self._token_counter,
        )
        if not chunks:
            return [stripped]
        return [chunk.text.strip() for chunk in chunks if chunk.text.strip()]

    def _wrap_text_for_chunking(self, text: str) -> str:
        wrapped_lines: list[str] = []
        for raw_line in text.splitlines():
            if len(raw_line) <= 200:
                wrapped_lines.append(raw_line)
                continue
            wrapped_lines.extend(
                textwrap.wrap(
                    raw_line,
                    width=200,
                    replace_whitespace=False,
                    drop_whitespace=False,
                    break_long_words=False,
                    break_on_hyphens=False,
                )
            )
        return "\n".join(wrapped_lines)

    def _parse_section_index(self, value: Any) -> int:
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return 1
        return max(1, parsed)


class _DuckDuckGoHtmlParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.results: list[dict[str, str]] = []
        self._current: dict[str, str] | None = None
        self._title_parts: list[str] = []
        self._snippet_parts: list[str] = []
        self._in_title = False
        self._in_snippet = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {key: value or "" for key, value in attrs}
        classes = set(attr_map.get("class", "").split())
        if tag == "a" and "result__a" in classes:
            self._flush_current()
            self._current = {"url": _normalize_duckduckgo_url(attr_map.get("href", ""))}
            self._title_parts = []
            self._snippet_parts = []
            self._in_title = True
            return
        if self._current is None:
            return
        if "result__snippet" in classes:
            self._in_snippet = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._in_title:
            self._in_title = False
            return
        if self._in_snippet and tag in {"a", "div", "span"}:
            self._in_snippet = False

    def handle_data(self, data: str) -> None:
        if self._current is None:
            return
        if self._in_title:
            self._title_parts.append(data)
        elif self._in_snippet:
            self._snippet_parts.append(data)

    def close(self) -> None:
        super().close()
        self._flush_current()

    def _flush_current(self) -> None:
        if self._current is None:
            return
        title = " ".join(part.strip() for part in self._title_parts if part.strip()).strip()
        snippet = " ".join(part.strip() for part in self._snippet_parts if part.strip()).strip()
        if title and self._current.get("url"):
            self.results.append(
                {
                    "title": title,
                    "url": self._current["url"],
                    "snippet": snippet,
                }
            )
        self._current = None
        self._title_parts = []
        self._snippet_parts = []
        self._in_title = False
        self._in_snippet = False


def _normalize_duckduckgo_url(raw_url: str) -> str:
    if not raw_url:
        return ""
    if raw_url.startswith("//"):
        raw_url = "https:" + raw_url
    parsed = urllib.parse.urlparse(raw_url)
    if parsed.netloc.endswith("duckduckgo.com") and parsed.path == "/l/":
        uddg = urllib.parse.parse_qs(parsed.query).get("uddg", [])
        if uddg:
            return urllib.parse.unquote(uddg[0])
    return raw_url


def _load_research_system_prompt() -> str:
    return resources.files("vibe_code_scanner").joinpath("scanner_research_prompt.txt").read_text(
        encoding="utf-8"
    ).strip()


def _parse_action_response(response_text: str) -> dict[str, Any]:
    try:
        payload = load_json_object(response_text)
    except ResponseParseError as exc:
        raise ResearchError("response was not valid JSON") from exc
    action = payload.get("action")
    if not isinstance(action, str) or not action.strip():
        raise ResearchError("response must include a non-empty action")
    payload["action"] = action.strip()
    return payload


def _clean_html_text(raw_text: str) -> str:
    without_scripts = SCRIPT_STYLE_PATTERN.sub(" ", raw_text)
    without_tags = TAG_PATTERN.sub(" ", without_scripts)
    normalized = WHITESPACE_PATTERN.sub(" ", unescape(without_tags))
    return normalized.strip()


def _truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)].rstrip() + "..."


def _format_line_range(line_start: int | None, line_end: int | None) -> str:
    if line_start is None and line_end is None:
        return "unknown"
    if line_start == line_end or line_end is None:
        return str(line_start)
    if line_start is None:
        return str(line_end)
    return f"{line_start}-{line_end}"


def _severity_rank(severity: str) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return order.get(severity, 5)


def _confidence_rank(confidence: str) -> int:
    order = {"high": 0, "medium": 1, "low": 2}
    return order.get(confidence, 3)
