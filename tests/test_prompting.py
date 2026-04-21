from pathlib import Path
import tempfile
import unittest

from vibe_code_scanner.models import CodeChunk, ScanMode, SourceFile
from vibe_code_scanner.prompting import build_messages, load_system_prompt


class PromptingTests(unittest.TestCase):
    def test_build_messages_loads_system_prompt_from_external_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_file = SourceFile(
                root_path=root,
                path=root / "app.py",
                relative_path="app.py",
                size_bytes=32,
                language_hint="python",
            )
            chunk = CodeChunk(
                chunk_index=1,
                total_chunks=1,
                start_line=1,
                end_line=2,
                text="print('hello')\n",
                estimated_tokens=4,
                overlap_from_previous_tokens=0,
                overlap_from_previous_lines=0,
            )

            messages = build_messages(source_file, chunk, scan_mode=ScanMode.SECURITY_AND_QUALITY)

        self.assertEqual(messages[0]["content"], load_system_prompt())
        self.assertIn("Return exactly one JSON object.", messages[0]["content"])
        self.assertIn("Do not emit <think> tags", messages[0]["content"])
        self.assertIn("Return one JSON object only.", messages[1]["content"])
        self.assertIn('prefer {"findings": []}', messages[1]["content"])
