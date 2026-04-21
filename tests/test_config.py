from pathlib import Path
import tempfile
import unittest

from vibe_code_scanner.config import build_config


class ConfigTests(unittest.TestCase):
    def test_build_config_parses_sampling_settings(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = build_config(
                {
                    "__config_dir__": str(root),
                    "root_path": ".",
                    "export_dir": "scan-runs",
                    "base_url": "http://127.0.0.1:8000",
                    "model_name": "Qwen3.5-9B-local",
                    "include_globs": ["**/*.py"],
                    "temperature": 0.6,
                    "top_p": 0.95,
                    "top_k": 20,
                    "min_p": 0.0,
                    "presence_penalty": 0.0,
                    "repetition_penalty": 1.0,
                    "thinking_token_budget_enabled": False,
                    "thinking_token_budget": 2048,
                }
            )

        self.assertEqual(config.temperature, 0.6)
        self.assertEqual(config.top_p, 0.95)
        self.assertEqual(config.top_k, 20)
        self.assertEqual(config.min_p, 0.0)
        self.assertEqual(config.presence_penalty, 0.0)
        self.assertEqual(config.repetition_penalty, 1.0)
        self.assertFalse(config.thinking_token_budget_enabled)
        self.assertEqual(config.thinking_token_budget, 2048)
        self.assertIsNone(config.research_max_tokens_per_request)
        self.assertIsNone(config.research_thinking_token_budget)

    def test_duckduckgo_search_backend_does_not_require_base_url(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = build_config(
                {
                    "__config_dir__": str(root),
                    "root_path": ".",
                    "export_dir": "scan-runs",
                    "base_url": "http://127.0.0.1:8000",
                    "model_name": "Qwen3.5-9B-local",
                    "include_globs": ["**/*.py"],
                    "search_backend": "duckduckgo",
                    "search_base_url": "",
                }
            )

        self.assertEqual(config.search_backend.value, "duckduckgo")
        self.assertIsNone(config.search_base_url)

    def test_research_budget_overrides_are_parsed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = build_config(
                {
                    "__config_dir__": str(root),
                    "root_path": ".",
                    "export_dir": "scan-runs",
                    "base_url": "http://127.0.0.1:8000",
                    "model_name": "Qwen3.5-9B-local",
                    "include_globs": ["**/*.py"],
                    "research_max_tokens_per_request": 2048,
                    "research_thinking_token_budget": 8192,
                }
            )

        self.assertEqual(config.research_max_tokens_per_request, 2048)
        self.assertEqual(config.research_thinking_token_budget, 8192)

    def test_max_context_profile_rewrites_token_settings(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            config = build_config(
                {
                    "__config_dir__": str(root),
                    "root_path": ".",
                    "export_dir": "scan-runs",
                    "base_url": "http://127.0.0.1:8000",
                    "model_name": "Qwen3.5-9B-local",
                    "include_globs": ["**/*.py"],
                    "max_context": True,
                    "max_context_max_tokens_per_request": 81920,
                    "max_context_total_context_window_tokens": 262144,
                }
            )

        self.assertEqual(config.max_tokens_per_request, 81920)
        self.assertEqual(config.chunk_target_tokens, 180224)
        self.assertFalse(config.thinking_token_budget_enabled)
        self.assertEqual(config.research_max_tokens_per_request, 81920)
        self.assertIsNone(config.research_thinking_token_budget)
