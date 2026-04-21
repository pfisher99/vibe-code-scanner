from pathlib import Path
import asyncio
import tempfile
import unittest
from unittest.mock import patch

from vibe_code_scanner.client import OpenAICompatibleClient
from vibe_code_scanner.models import ApiStyle, AppConfig, ScanMode, TokenizerMode


def make_config(root: Path, *, trace: bool = False) -> AppConfig:
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
        include_globs=["**/*.py"],
        exclude_globs=[],
        ignored_directories=[],
        trace_enabled=trace,
        tokenizer_mode=TokenizerMode.HEURISTIC,
    )


class ClientTests(unittest.TestCase):
    def test_chat_completion_payload_uses_configured_sampling_parameters(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = make_config(Path(temp_dir))
            config.temperature = 0.6
            config.top_p = 0.95
            config.top_k = 20
            config.min_p = 0.0
            config.presence_penalty = 0.0
            config.repetition_penalty = 1.0
            client = OpenAICompatibleClient(config)

            payload = client._build_payload(
                [{"role": "user", "content": "review this"}],
                use_response_format=True,
            )

        self.assertEqual(payload["temperature"], 0.6)
        self.assertEqual(payload["top_p"], 0.95)
        self.assertEqual(payload["top_k"], 20)
        self.assertEqual(payload["min_p"], 0.0)
        self.assertEqual(payload["presence_penalty"], 0.0)
        self.assertEqual(payload["repetition_penalty"], 1.0)
        self.assertEqual(payload["extra_body"]["thinking_token_budget"], 4096)

    def test_chat_completion_payload_omits_thinking_budget_when_disabled(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = make_config(Path(temp_dir))
            config.thinking_token_budget_enabled = False
            client = OpenAICompatibleClient(config)

            payload = client._build_payload(
                [{"role": "user", "content": "review this"}],
                use_response_format=True,
            )

        self.assertNotIn("extra_body", payload)

    def test_chat_completion_payload_accepts_research_budget_overrides(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = make_config(Path(temp_dir))
            client = OpenAICompatibleClient(config)

            payload = client._build_payload(
                [{"role": "user", "content": "review this"}],
                use_response_format=True,
                max_tokens_per_request=1024,
                thinking_token_budget=2048,
            )

        self.assertEqual(payload["max_tokens"], 1024)
        self.assertEqual(payload["extra_body"]["thinking_token_budget"], 2048)

    def test_analyze_messages_captures_trace_request_messages(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            client = OpenAICompatibleClient(make_config(Path(temp_dir), trace=True))
            messages = [{"role": "user", "content": "review this"}]

            with patch.object(
                client,
                "_post_json",
                return_value={"choices": [{"message": {"content": '{"findings":[]}'}}]},
            ):
                response_text, raw_payload, trace = asyncio.run(client.analyze_messages(messages))

        self.assertEqual(response_text, '{"findings":[]}')
        self.assertEqual(raw_payload["choices"][0]["message"]["content"], '{"findings":[]}')
        self.assertIsNotNone(trace)
        self.assertEqual(trace.request_messages, messages)


if __name__ == "__main__":
    unittest.main()
