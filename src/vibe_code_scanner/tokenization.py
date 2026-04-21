"""Token counting helpers used for chunk sizing."""

from __future__ import annotations

import json
import logging
import math
import urllib.error
import urllib.request
from typing import Protocol

from .models import AppConfig, TokenizerMode

LOGGER = logging.getLogger("vibe_code_scanner")
TOKENIZER_REQUEST_TIMEOUT_SECONDS = 15.0


class TokenizationError(RuntimeError):
    """Raised when chunk token counting cannot be performed."""


class TokenCounter(Protocol):
    def count(self, text: str) -> int:
        """Return the token count for the provided text."""


class HeuristicTokenCounter:
    """Conservative character-based fallback for endpoints without tokenization."""

    def count(self, text: str) -> int:
        if not text:
            return 0
        return max(1, math.ceil(len(text) / 3.5))


class VllmTokenCounter:
    """Use vLLM's tokenizer endpoint for exact chunk sizing."""

    def __init__(self, config: AppConfig, *, allow_fallback: bool) -> None:
        self._config = config
        self._endpoint = _tokenize_endpoint_url(config.base_url)
        self._fallback = HeuristicTokenCounter() if allow_fallback else None
        self._remote_available: bool | None = None
        self._fallback_reason: str | None = None
        self._warned_fallback = False

    def count(self, text: str) -> int:
        if not text:
            return 0

        if self._remote_available is False:
            if self._fallback is None:
                raise TokenizationError(self._fallback_reason or "Tokenizer endpoint is unavailable.")
            return self._fallback.count(text)

        try:
            count = self._post_count(text)
        except TokenizationError as exc:
            if self._remote_available is True or self._fallback is None:
                raise
            self._remote_available = False
            self._fallback_reason = str(exc)
            if not self._warned_fallback:
                LOGGER.warning(
                    "Tokenizer endpoint %s is unavailable (%s). Falling back to heuristic chunk sizing.",
                    self._endpoint,
                    exc,
                )
                self._warned_fallback = True
            return self._fallback.count(text)

        self._remote_available = True
        return count

    def _post_count(self, text: str) -> int:
        body = json.dumps({"model": self._config.model_name, "prompt": text}).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self._config.api_key:
            headers["Authorization"] = f"Bearer {self._config.api_key}"
        request = urllib.request.Request(self._endpoint, data=body, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(
                request,
                timeout=max(1.0, min(TOKENIZER_REQUEST_TIMEOUT_SECONDS, self._config.request_timeout_seconds)),
            ) as response:
                charset = response.headers.get_content_charset("utf-8")
                raw_text = response.read().decode(charset)
        except urllib.error.HTTPError as exc:
            error_text = exc.read().decode("utf-8", errors="replace").strip()
            detail = f"{error_text}" if error_text else "no error body"
            raise TokenizationError(f"HTTP {exc.code} from tokenizer endpoint: {detail}") from exc
        except urllib.error.URLError as exc:
            raise TokenizationError(f"could not reach tokenizer endpoint: {exc.reason}") from exc

        try:
            payload = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            raise TokenizationError("tokenizer endpoint returned non-JSON data") from exc
        if not isinstance(payload, dict):
            raise TokenizationError("tokenizer endpoint returned an unexpected JSON shape")

        count = payload.get("count")
        if isinstance(count, int) and count >= 0:
            return count
        tokens = payload.get("tokens")
        if isinstance(tokens, list):
            return len(tokens)
        raise TokenizationError("tokenizer endpoint response did not include a token count")


def build_token_counter(config: AppConfig) -> TokenCounter:
    if config.tokenizer_mode == TokenizerMode.HEURISTIC:
        return HeuristicTokenCounter()
    if config.tokenizer_mode == TokenizerMode.VLLM:
        return VllmTokenCounter(config, allow_fallback=False)
    return VllmTokenCounter(config, allow_fallback=True)


def _tokenize_endpoint_url(base_url: str) -> str:
    base = base_url.rstrip("/")
    if base.endswith("/v1"):
        base = base[: -len("/v1")]
    return f"{base}/tokenize"
