"""OpenAI-compatible model client for local endpoints."""

from __future__ import annotations

import asyncio
from copy import deepcopy
import json
import urllib.error
import urllib.request
from typing import Any

from .models import ApiStyle, AppConfig, ChunkTraceData


class ModelClientError(RuntimeError):
    """Raised when the configured model endpoint cannot be used successfully."""


class OpenAICompatibleClient:
    def __init__(self, config: AppConfig) -> None:
        self._config = config

    async def analyze_messages(
        self,
        messages: list[dict[str, str]],
        *,
        max_tokens_per_request: int | None = None,
        thinking_token_budget: int | None = None,
    ) -> tuple[str, dict[str, Any], ChunkTraceData | None]:
        last_error: Exception | None = None
        use_response_format = True
        attempt = 0
        trace_data = (
            ChunkTraceData(
                request_messages=deepcopy(messages) if self._config.trace_enabled else None,
            )
            if self._config.trace_enabled
            else None
        )

        while attempt <= self._config.retry_count:
            try:
                payload = self._build_payload(
                    messages,
                    use_response_format=use_response_format,
                    max_tokens_per_request=max_tokens_per_request,
                    thinking_token_budget=thinking_token_budget,
                )
                response_json = await asyncio.to_thread(self._post_json, payload)
                response_text = self._extract_response_text(response_json)
                return response_text, response_json, trace_data
            except _UnsupportedResponseFormat:
                use_response_format = False
                continue
            except Exception as exc:
                last_error = exc
                if attempt >= self._config.retry_count:
                    break
                await asyncio.sleep(min(8.0, 0.75 * (2**attempt)))
                attempt += 1

        raise ModelClientError(str(last_error or "Model request failed."))

    def _build_payload(
        self,
        messages: list[dict[str, str]],
        *,
        use_response_format: bool,
        max_tokens_per_request: int | None = None,
        thinking_token_budget: int | None = None,
    ) -> dict[str, Any]:
        resolved_max_tokens = max_tokens_per_request or self._config.max_tokens_per_request
        extra_body = self._build_extra_body(thinking_token_budget=thinking_token_budget)
        if self._config.api_style == ApiStyle.RESPONSES:
            payload: dict[str, Any] = {
                "model": self._config.model_name,
                "input": messages,
                "max_output_tokens": resolved_max_tokens,
                "temperature": self._config.temperature,
                "top_p": self._config.top_p,
                "presence_penalty": self._config.presence_penalty,
            }
            if use_response_format:
                payload["text"] = {"format": {"type": "json_object"}}
            if extra_body:
                payload["extra_body"] = extra_body
            return payload

        payload = {
            "model": self._config.model_name,
            "messages": messages,
            "max_tokens": resolved_max_tokens,
            "temperature": self._config.temperature,
            "top_p": self._config.top_p,
            "top_k": self._config.top_k,
            "min_p": self._config.min_p,
            "presence_penalty": self._config.presence_penalty,
            "repetition_penalty": self._config.repetition_penalty,
        }
        if use_response_format:
            payload["response_format"] = {"type": "json_object"}
        if extra_body:
            payload["extra_body"] = extra_body
        return payload

    def _build_extra_body(self, *, thinking_token_budget: int | None = None) -> dict[str, Any]:
        extra_body: dict[str, Any] = {}
        resolved_thinking_budget = (
            thinking_token_budget
            if thinking_token_budget is not None
            else (self._config.thinking_token_budget if self._config.thinking_token_budget_enabled else None)
        )
        if resolved_thinking_budget is not None:
            extra_body["thinking_token_budget"] = resolved_thinking_budget
        return extra_body

    def _post_json(self, payload: dict[str, Any]) -> dict[str, Any]:
        endpoint = self._endpoint_url()
        body = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self._config.api_key:
            headers["Authorization"] = f"Bearer {self._config.api_key}"
        request = urllib.request.Request(endpoint, data=body, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(request, timeout=self._config.request_timeout_seconds) as response:
                charset = response.headers.get_content_charset("utf-8")
                raw_text = response.read().decode(charset)
        except urllib.error.HTTPError as exc:
            error_text = exc.read().decode("utf-8", errors="replace")
            if exc.code == 400 and "response_format" in error_text:
                raise _UnsupportedResponseFormat() from exc
            raise ModelClientError(
                self._format_http_error(endpoint, exc.code, error_text)
            ) from exc
        except urllib.error.URLError as exc:
            raise ModelClientError(f"Could not reach model endpoint {endpoint}: {exc.reason}") from exc

        try:
            payload_json = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            raise ModelClientError("Model endpoint returned non-JSON data.") from exc
        if not isinstance(payload_json, dict):
            raise ModelClientError("Model endpoint returned an unexpected JSON shape.")
        return payload_json

    def _endpoint_url(self) -> str:
        base = self._config.base_url.rstrip("/")
        if not base.endswith("/v1"):
            base = f"{base}/v1"
        if self._config.api_style == ApiStyle.RESPONSES:
            return f"{base}/responses"
        return f"{base}/chat/completions"

    def _extract_response_text(self, payload: dict[str, Any]) -> str:
        if self._config.api_style == ApiStyle.RESPONSES:
            output_text = payload.get("output_text")
            if isinstance(output_text, str) and output_text.strip():
                return output_text
            output = payload.get("output", [])
            if isinstance(output, list):
                for item in output:
                    if not isinstance(item, dict):
                        continue
                    for content in item.get("content", []):
                        if not isinstance(content, dict):
                            continue
                        text_value = content.get("text")
                        if isinstance(text_value, str) and text_value.strip():
                            return text_value
            raise ModelClientError("Responses API payload did not contain output text.")

        choices = payload.get("choices")
        if not isinstance(choices, list) or not choices:
            raise ModelClientError("Chat completions payload did not contain choices.")
        message = choices[0].get("message", {})
        content = message.get("content")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts: list[str] = []
            for item in content:
                if isinstance(item, dict) and item.get("type") == "text":
                    text_value = item.get("text")
                    if isinstance(text_value, str):
                        parts.append(text_value)
            if parts:
                return "\n".join(parts)
        raise ModelClientError("Chat completions payload did not contain text content.")

    def _format_http_error(self, endpoint: str, status_code: int, error_text: str) -> str:
        normalized = error_text.strip() or "No error body returned."
        message = f"HTTP {status_code} from model endpoint {endpoint}: {normalized}"
        if self._config.thinking_token_budget_enabled:
            message += (
                " If thinking_token_budget is enabled, make sure the endpoint supports"
                " extra_body.thinking_token_budget and that vLLM was started with a"
                " reasoning parser/config for Qwen-style thinking output."
            )
        return message


class _UnsupportedResponseFormat(Exception):
    pass
