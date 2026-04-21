from pathlib import Path
import asyncio
from contextlib import redirect_stdout
import io
import tempfile
import unittest
from unittest.mock import patch

from vibe_code_scanner.client import OpenAICompatibleClient
from vibe_code_scanner.models import ApiStyle, AppConfig, ScanMode
from vibe_code_scanner.tracing import LiveTracePrinter


def make_config(root: Path, *, trace: bool = False, trace_live: bool = False) -> AppConfig:
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
        trace_live_enabled=trace_live,
    )


class ClientTests(unittest.TestCase):
    def test_streaming_chat_completions_accumulates_text_and_trace(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            client = OpenAICompatibleClient(make_config(Path(temp_dir), trace=True, trace_live=True))
            messages = [{"role": "user", "content": "review this"}]
            stdout_buffer = io.StringIO()

            with (
                patch("vibe_code_scanner.client.urllib.request.urlopen", return_value=_FakeSseResponse()),
                redirect_stdout(stdout_buffer),
            ):
                response_text, raw_payload, trace = asyncio.run(
                    client.analyze_messages(
                        messages,
                        trace_label="worker-1",
                        live_trace_printer=LiveTracePrinter(),
                    )
                )

        self.assertEqual(response_text, "<think>checking</think>{\"findings\":[]}")
        self.assertTrue(raw_payload["streamed"])
        self.assertIsNotNone(trace)
        self.assertTrue(trace.used_streaming)
        self.assertEqual(trace.request_messages, messages)
        output = stdout_buffer.getvalue()
        self.assertIn("=== thinking: worker-1 ===", output)
        self.assertIn("checking", output)
        self.assertIn("=== end thinking ===", output)
        self.assertNotIn('{"findings":[]}', output)

    def test_live_trace_printer_focuses_on_first_thinking_stream_only(self) -> None:
        printer = LiveTracePrinter()
        stdout_buffer = io.StringIO()

        with redirect_stdout(stdout_buffer):
            printer.start("worker-1")
            printer.start("worker-2")
            printer.delta("worker-1", "<think>first stream")
            printer.delta("worker-2", "<think>second stream")
            printer.delta("worker-1", " continues</think>{\"findings\":[]}")
            printer.finish("worker-1")
            printer.finish("worker-2")

        output = stdout_buffer.getvalue()
        self.assertIn("=== thinking: worker-1 ===", output)
        self.assertIn("first stream continues", output)
        self.assertNotIn("worker-2", output)
        self.assertNotIn("second stream", output)
        self.assertNotIn('{"findings":', output)


class _FakeHeaders:
    def get_content_charset(self, default: str) -> str:
        return default


class _FakeSseResponse:
    headers = _FakeHeaders()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def __iter__(self):
        return iter(
            [
                b'data: {"choices":[{"delta":{"content":"<think>checking</think>"}}]}\n',
                b'data: {"choices":[{"delta":{"content":"{\\"findings\\":[]}"}}]}\n',
                b"data: [DONE]\n",
            ]
        )


if __name__ == "__main__":
    unittest.main()
