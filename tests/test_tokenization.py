from pathlib import Path
import json
import tempfile
import unittest
import urllib.error
from unittest.mock import patch

from vibe_code_scanner.models import ApiStyle, AppConfig, ScanMode, TokenizerMode
from vibe_code_scanner.tokenization import HeuristicTokenCounter, build_token_counter


def make_config(root: Path, *, tokenizer_mode: TokenizerMode) -> AppConfig:
    return AppConfig(
        root_path=root,
        export_dir=root / "out",
        base_url="http://127.0.0.1:8000",
        model_name="Qwen3.5-9B-local",
        api_style=ApiStyle.CHAT_COMPLETIONS,
        scan_mode=ScanMode.SECURITY_AND_QUALITY,
        max_concurrent_requests=2,
        max_tokens_per_request=512,
        chunk_target_tokens=200,
        chunk_overlap_tokens=20,
        request_timeout_seconds=10.0,
        retry_count=1,
        max_file_size_bytes=1024 * 1024,
        include_globs=["**/*.py"],
        exclude_globs=[],
        ignored_directories=[],
        tokenizer_mode=tokenizer_mode,
    )


class TokenizationTests(unittest.TestCase):
    def test_vllm_token_counter_uses_tokenize_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = make_config(Path(temp_dir), tokenizer_mode=TokenizerMode.VLLM)
            counter = build_token_counter(config)

            with patch(
                "vibe_code_scanner.tokenization.urllib.request.urlopen",
                return_value=_FakeJsonResponse({"count": 7}),
            ) as mocked_urlopen:
                count = counter.count("hello world")

        self.assertEqual(count, 7)
        request = mocked_urlopen.call_args.args[0]
        self.assertEqual(request.full_url, "http://127.0.0.1:8000/tokenize")
        self.assertEqual(
            json.loads(request.data.decode("utf-8")),
            {"model": "Qwen3.5-9B-local", "prompt": "hello world"},
        )

    def test_auto_token_counter_falls_back_once_when_tokenizer_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = make_config(Path(temp_dir), tokenizer_mode=TokenizerMode.AUTO)
            counter = build_token_counter(config)
            expected = HeuristicTokenCounter().count("hello world")

            with patch(
                "vibe_code_scanner.tokenization.urllib.request.urlopen",
                side_effect=urllib.error.URLError("connection refused"),
            ) as mocked_urlopen:
                first_count = counter.count("hello world")
                second_count = counter.count("hello world again")

        self.assertEqual(first_count, expected)
        self.assertGreater(second_count, first_count)
        self.assertEqual(mocked_urlopen.call_count, 1)


class _FakeHeaders:
    def get_content_charset(self, default: str) -> str:
        return default


class _FakeJsonResponse:
    headers = _FakeHeaders()

    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self) -> bytes:
        return json.dumps(self._payload).encode("utf-8")
