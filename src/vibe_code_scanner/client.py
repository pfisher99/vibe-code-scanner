"""OpenAI-compatible model client for local endpoints."""

from __future__ import annotations

import asyncio
from copy import deepcopy
import json
import urllib.error
import urllib.request
from typing import Any

from .models import ApiStyle, AppConfig, ChunkTraceData
from .tracing import LiveTracePrinter


class ModelClientError(RuntimeError):
    """Raised when the configured model endpoint cannot be used successfully."""


class OpenAICompatibleClient:
    def __init__(self, config: AppConfig) -> None:
        self._config = config

    async def analyze_messages(
        self,
        messages: list[dict[str, str]],
        *,
        trace_label: str | None = None,
        live_trace_printer: LiveTracePrinter | None = None,
    ) -> tuple[str, dict[str, Any], ChunkTraceData | None]:
        last_error: Exception | None = None
        use_response_format = True
        use_streaming = self._config.trace_live_enabled and trace_label is not None and live_trace_printer is not None
        attempt = 0
        trace_data = (
            ChunkTraceData(
                request_messages=deepcopy(messages) if self._config.trace_enabled else None,
                used_streaming=False,
                live_streaming_requested=use_streaming,
            )
            if (self._config.trace_enabled or use_streaming)
            else None
        )

        while attempt <= self._config.retry_count:
            try:
                payload = self._build_payload(
                    messages,
                    use_response_format=use_response_format,
                    use_streaming=use_streaming,
                )
                if use_streaming:
                    response_text, response_json = await asyncio.to_thread(
                        self._stream_json,
                        payload,
                        trace_label,
                        live_trace_printer,
                    )
                    if trace_data is not None:
                        trace_data.used_streaming = True
                else:
                    response_json = await asyncio.to_thread(self._post_json, payload)
                    response_text = self._extract_response_text(response_json)
                return response_text, response_json, trace_data
            except _UnsupportedResponseFormat:
                use_response_format = False
                continue
            except _UnsupportedStreaming as exc:
                use_streaming = False
                if trace_data is not None:
                    trace_data.stream_fallback_reason = str(exc)
                if live_trace_printer is not None and trace_label is not None:
                    live_trace_printer.notice(trace_label, str(exc))
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
        use_streaming: bool,
    ) -> dict[str, Any]:
        if self._config.api_style == ApiStyle.RESPONSES:
            payload: dict[str, Any] = {
                "model": self._config.model_name,
                "input": messages,
                "max_output_tokens": self._config.max_tokens_per_request,
            }
            if use_response_format:
                payload["text"] = {"format": {"type": "json_object"}}
            if use_streaming:
                payload["stream"] = True
            return payload

        payload = {
            "model": self._config.model_name,
            "messages": messages,
            "max_tokens": self._config.max_tokens_per_request,
            "temperature": 0,
        }
        if use_response_format:
            payload["response_format"] = {"type": "json_object"}
        if use_streaming:
            payload["stream"] = True
        return payload

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
                f"HTTP {exc.code} from model endpoint {endpoint}: {error_text.strip()}"
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

    def _stream_json(
        self,
        payload: dict[str, Any],
        trace_label: str | None,
        live_trace_printer: LiveTracePrinter | None,
    ) -> tuple[str, dict[str, Any]]:
        endpoint = self._endpoint_url()
        body = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self._config.api_key:
            headers["Authorization"] = f"Bearer {self._config.api_key}"
        request = urllib.request.Request(endpoint, data=body, headers=headers, method="POST")

        started_trace = False
        try:
            with urllib.request.urlopen(request, timeout=self._config.request_timeout_seconds) as response:
                charset = response.headers.get_content_charset("utf-8")
                if live_trace_printer is not None and trace_label is not None:
                    live_trace_printer.start(trace_label)
                    started_trace = True
                parts: list[str] = []
                event_count = 0
                for raw_line in response:
                    line = raw_line.decode(charset).strip()
                    if not line or not line.startswith("data:"):
                        continue
                    data = line[5:].strip()
                    if data == "[DONE]":
                        break
                    event_count += 1
                    try:
                        event_payload = json.loads(data)
                    except json.JSONDecodeError:
                        continue
                    delta_text = self._extract_stream_delta_text(event_payload)
                    if delta_text:
                        parts.append(delta_text)
                        if live_trace_printer is not None and trace_label is not None:
                            live_trace_printer.delta(trace_label, delta_text)
        except urllib.error.HTTPError as exc:
            error_text = exc.read().decode("utf-8", errors="replace")
            if exc.code == 400 and "response_format" in error_text:
                raise _UnsupportedResponseFormat() from exc
            if exc.code == 400 and "stream" in error_text.lower():
                raise _UnsupportedStreaming("Streaming not supported by this endpoint, falling back to buffered mode.") from exc
            raise ModelClientError(
                f"HTTP {exc.code} from model endpoint {endpoint}: {error_text.strip()}"
            ) from exc
        except urllib.error.URLError as exc:
            raise ModelClientError(f"Could not reach model endpoint {endpoint}: {exc.reason}") from exc
        finally:
            if started_trace and live_trace_printer is not None and trace_label is not None:
                live_trace_printer.finish(trace_label)

        response_text = "".join(parts)
        if not response_text.strip():
            raise ModelClientError("Streaming response completed without any text content.")
        return response_text, {
            "streamed": True,
            "api_style": self._config.api_style.value,
            "event_count": event_count,
        }

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

    def _extract_stream_delta_text(self, payload: dict[str, Any]) -> str:
        if self._config.api_style == ApiStyle.RESPONSES:
            event_type = str(payload.get("type", ""))
            if event_type.endswith(".delta"):
                return self._coerce_text(payload.get("delta"))
            return ""

        choices = payload.get("choices")
        if not isinstance(choices, list) or not choices:
            return ""
        delta = choices[0].get("delta", {})
        if not isinstance(delta, dict):
            return ""

        parts = [
            self._coerce_text(delta.get("content")),
            self._coerce_text(delta.get("text")),
            self._coerce_text(delta.get("reasoning_content")),
            self._coerce_text(delta.get("reasoning")),
        ]
        return "".join(part for part in parts if part)

    def _coerce_text(self, value: Any) -> str:
        if isinstance(value, str):
            return value
        if isinstance(value, list):
            parts: list[str] = []
            for item in value:
                if isinstance(item, str):
                    parts.append(item)
                elif isinstance(item, dict):
                    for key in ("text", "content", "reasoning_content"):
                        text_value = item.get(key)
                        if isinstance(text_value, str):
                            parts.append(text_value)
            return "".join(parts)
        if isinstance(value, dict):
            return self._coerce_text([value])
        return ""


class _UnsupportedResponseFormat(Exception):
    pass


class _UnsupportedStreaming(Exception):
    pass
