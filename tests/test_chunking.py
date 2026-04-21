from pathlib import Path
import tempfile
import unittest

from vibe_code_scanner.chunking import chunk_text
from vibe_code_scanner.models import ApiStyle, AppConfig, ScanMode, TokenizerMode


def make_config(root: Path) -> AppConfig:
    return AppConfig(
        root_path=root,
        export_dir=root / "out",
        base_url="http://127.0.0.1:8000",
        model_name="test-model",
        api_style=ApiStyle.CHAT_COMPLETIONS,
        scan_mode=ScanMode.SECURITY_AND_QUALITY,
        max_concurrent_requests=2,
        max_tokens_per_request=512,
        chunk_target_tokens=20,
        chunk_overlap_tokens=8,
        request_timeout_seconds=10.0,
        retry_count=1,
        max_file_size_bytes=1024 * 1024,
        include_globs=["**/*.py"],
        exclude_globs=[],
        ignored_directories=[],
        tokenizer_mode=TokenizerMode.HEURISTIC,
    )


class ChunkingTests(unittest.TestCase):
    def test_chunk_text_creates_overlapping_chunks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config = make_config(Path(temp_dir))
            text = "".join(f"line_{index} = '{index:02d}'\n" for index in range(1, 12))

            chunks = chunk_text(text, config, token_counter=_WhitespaceTokenCounter())

            self.assertGreater(len(chunks), 1)
            self.assertGreater(chunks[1].overlap_from_previous_lines, 0)
            self.assertLessEqual(chunks[1].start_line, chunks[0].end_line)
            self.assertEqual(chunks[-1].total_chunks, len(chunks))
            self.assertLessEqual(chunks[0].estimated_tokens, config.chunk_target_tokens)


class _WhitespaceTokenCounter:
    def count(self, text: str) -> int:
        return len(text.split())


if __name__ == "__main__":
    unittest.main()
