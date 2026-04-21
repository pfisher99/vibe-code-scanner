# Vibe Code Scanner

`vibe-code-scanner` is a local AI-assisted CLI for scanning a source tree with an OpenAI-compatible model endpoint such as vLLM. It walks a repository, skips generated and binary content, chunks source files by a token budget, asks the model for strict JSON findings per chunk, deduplicates overlaps, and renders markdown plus machine-readable artifacts for each run.

This project is built to run locally against a model that fits on a 16GB GPU, rather than depending on a hosted scanning service.

TOML is used for configuration because Python 3.11 ships `tomllib` in the standard library, so the scanner can stay dependency-light while still having a real config format.

## Features

- Recursive source-tree discovery with sensible default ignore directories
- Include and exclude glob controls
- Binary and large-file skipping
- Token-based chunking with configurable overlap, using the model tokenizer when available
- OpenAI-compatible chat or responses style API client
- Conservative JSON-only review prompt with explicit `no findings` behavior
- Per-chunk raw artifacts, per-file markdown reports, top-level summary markdown, and `findings.json`
- Retry and timeout handling with partial-run completion
- Local path scans or public GitHub repo scans via `git clone`
- Optional per-chunk trace artifacts for local debugging
- Optional final research pass where the model inspects the completed scan outputs and can use web lookup tools when configured

## Install

```bash
python -m pip install -e .
```

## Quick Start

1. Start a local OpenAI-compatible endpoint, for example vLLM, on `http://127.0.0.1:8000`.
2. Copy or edit [`scanner.example.toml`](scanner.example.toml).
3. Run the scanner against a local repository root:

```bash
vibe-code-scanner ../some-repo --config scanner.example.toml
```

To scan a public GitHub repository directly from the CLI:

```bash
vibe-code-scanner --repo https://github.com/OWASP/NodeGoat --ref master --config scanner.example.toml --scan-mode security --max-concurrency 4
```

To keep full per-chunk prompt traces:

```bash
vibe-code-scanner ../some-repo --config scanner.example.toml --trace
```

To run the final post-scan research pass:

```bash
vibe-code-scanner ../some-repo --config scanner.example.toml --research
```

To add optional web search tools to the final research pass through a SearXNG instance:

```bash
vibe-code-scanner ../some-repo --config scanner.example.toml --research --search-backend searxng --search-base-url http://127.0.0.1:8080
```

To use the built-in no-extra-dependency web search path:

```bash
vibe-code-scanner ../some-repo --config scanner.example.toml --research --search-backend duckduckgo
```

You can also override common settings directly for a local path:

```bash
vibe-code-scanner ../some-repo --model Qwen3.5-9B-local --base-url http://127.0.0.1:8000 --output scan-runs
```

For quick testing against only a random subset of eligible files:

```bash
vibe-code-scanner ../some-repo --config scanner.example.toml --max-files 10
```

## Config Example

See [`scanner.example.toml`](scanner.example.toml).

Important settings:

- `base_url`: OpenAI-compatible endpoint root. Defaults to `http://127.0.0.1:8000`.
- `model_name`: Model identifier sent to the endpoint.
- `tokenizer_mode`: `auto`, `vllm`, or `heuristic`. The sample config uses `vllm` so chunk sizing matches the local model tokenizer.
- `temperature`, `top_p`, `top_k`, `min_p`, `presence_penalty`, `repetition_penalty`: generation settings exposed in config. The defaults are tuned for local Qwen3.5 thinking-mode coding scans.
- `thinking_token_budget_enabled`: When `true`, the scanner sends a non-standard `extra_body.thinking_token_budget` field for reasoning-capable local endpoints such as vLLM with Qwen-style thinking support. Set it to `false` when using an external provider that does not support this field.
- `thinking_token_budget`: Maximum reasoning-budget tokens to ask the model to spend before switching to the final answer. The sample config defaults to `4096`.
- `research_max_tokens_per_request`: Optional research-only output limit. If omitted, research defaults to `2x` the normal `max_tokens_per_request`.
- `research_thinking_token_budget`: Optional research-only reasoning budget. If omitted, research defaults to `2x` the normal `thinking_token_budget`.
- `scan_mode`: `security` or `security_and_quality`.
- `chunk_target_tokens`: Approximate input chunk size.
- `chunk_overlap_tokens`: Approximate overlap between adjacent chunks.
- `max_tokens_per_request`: Maximum model output tokens.
- `request_timeout_seconds`: Per-request timeout. The sample config uses `300` seconds to leave room for long local generations.
- The sample config is tuned for a roughly `64k` per-request window: `50k` chunk target + up to `4k` output + prompt headroom.
- The sample model and token budget are intended for a local setup with a 16GB GPU.
- `research`: Enables a final LLM-guided research pass over the completed scan outputs.
- `max_files`: Optional testing limit. When set, the scanner samples a random subset of up to this many eligible files before scanning.
- `search_backend`: Optional search backend available to the final research pass. `duckduckgo` works without any extra local service. `searxng` is still available if you want to point at your own instance.
- `search_base_url`: Base URL for the configured search backend. This is only required for `searxng`.
- `research_max_results`: Maximum search results to return per research lookup.

## Output Layout

Each run creates a timestamped folder under `export_dir`:

```text
scan-runs/
  20260421-153012/
    index.md
    findings.json
    files/
      src/
        app.py.md
    research/
      final-report.md
    raw/
      chunks/
        src/
          app.py.chunk-0001.json
      files/
        src/
          app.py.json
      research/
        final-report.json
```

## CLI Usage

```text
usage: vibe-code-scanner [-h] [--config CONFIG] [--output OUTPUT]
                         [--repo REPO] [--ref REF]
                         [--base-url BASE_URL] [--model MODEL]
                         [--trace]
                         [--research] [--search-backend {none,searxng,duckduckgo}]
                         [--search-base-url SEARCH_BASE_URL]
                         [--scan-mode {security,security_and_quality}]
                         [--api-style {chat_completions,responses}]
                         [--max-concurrency MAX_CONCURRENCY]
                         [--max-files MAX_FILES]
                         [--log-level {DEBUG,INFO,WARNING,ERROR}]
                         [root]
```

## Notes

- The scanner only trusts issues visible in the current chunk and tells the model to return `{"findings": []}` when there are no meaningful findings.
- Chunking can use vLLM's `/tokenize` endpoint for exact chunk sizing. `tokenizer_mode = "auto"` falls back to the old conservative heuristic when an endpoint does not expose tokenizer support.
- The current client supports OpenAI-compatible `/v1/chat/completions` and `/v1/responses` payload shapes.
- `--repo` currently supports public GitHub repositories only, and requires `git` to be installed and available on `PATH`.
- `--trace` stores per-chunk prompt metadata in the raw chunk artifacts alongside the full buffered raw model response text.
- `--max-files` is a testing helper that randomly caps the number of eligible files scanned in a run.
- `thinking_token_budget` depends on server support. For vLLM, the endpoint needs reasoning enabled and configured for Qwen-style thinking output; otherwise the server may reject the request. If you are pointing the scanner at a different OpenAI-compatible provider, set `thinking_token_budget_enabled = false`.
- `--research` runs after the initial scan and lets the model perform a final pass over its own outputs. The first pass remains a from-memory code review.
- The final research pass can inspect scanner outputs on its own and optionally use `search_web` and `fetch_url` style tools when configured.
- The research loop now forces a more disciplined workflow: it must inspect the scan results first, read the most important file reports, and when web search is configured it must perform at least one search plus one fetched external reference before it can finish.
- Research tool outputs are paged to fit the configured request budget, using the same token-counting path as the scanner. Large file reports and fetched web pages can therefore be read section-by-section instead of overflowing a single request.
- The built-in web search path uses DuckDuckGo HTML search and requires no extra Python dependency or local search service.
- Optional web search still supports SearXNG if you want to point at your own instance.
- The scanner system prompt lives in [src/vibe_code_scanner/scanner_system_prompt.txt](/c:/Users/sqeak/source/vibe-code-scanner/src/vibe_code_scanner/scanner_system_prompt.txt) so you can tweak it without editing the Python prompt builder.
- The post-scan research-agent prompt lives in [src/vibe_code_scanner/scanner_research_prompt.txt](/c:/Users/sqeak/source/vibe-code-scanner/src/vibe_code_scanner/scanner_research_prompt.txt).
