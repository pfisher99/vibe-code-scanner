# Vibe Code Scanner

`vibe-code-scanner` is a local AI-assisted CLI for scanning a source tree with an OpenAI-compatible model endpoint such as vLLM. It walks a repository, skips generated and binary content, chunks source files by an approximate token budget, asks the model for strict JSON findings per chunk, deduplicates overlaps, and renders markdown plus machine-readable artifacts for each run.

TOML is used for configuration because Python 3.11 ships `tomllib` in the standard library, so the scanner can stay dependency-light while still having a real config format.

## Features

- Recursive source-tree discovery with sensible default ignore directories
- Include and exclude glob controls
- Binary and large-file skipping
- Approximate token-based chunking with configurable overlap
- OpenAI-compatible chat or responses style API client
- Conservative JSON-only review prompt with explicit `no findings` behavior
- Per-chunk raw artifacts, per-file markdown reports, top-level summary markdown, and `findings.json`
- Retry and timeout handling with partial-run completion
- Local path scans or public GitHub repo scans via `git clone`

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
vibe-code-scanner --repo https://github.com/OWASP/NodeGoat --ref main --config scanner.example.toml
```

You can also override common settings directly for a local path:

```bash
vibe-code-scanner ../some-repo --model Qwen/Qwen2.5-Coder-14B-Instruct --base-url http://127.0.0.1:8000 --output scan-runs
```

## Config Example

See [`scanner.example.toml`](scanner.example.toml).

Important settings:

- `base_url`: OpenAI-compatible endpoint root. Defaults to `http://127.0.0.1:8000`.
- `model_name`: Model identifier sent to the endpoint.
- `scan_mode`: `security` or `security_and_quality`.
- `chunk_target_tokens`: Approximate input chunk size.
- `chunk_overlap_tokens`: Approximate overlap between adjacent chunks.
- `max_tokens_per_request`: Maximum model output tokens.

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
    raw/
      chunks/
        src/
          app.py.chunk-0001.json
      files/
        src/
          app.py.json
```

## CLI Usage

```text
usage: vibe-code-scanner [-h] [--config CONFIG] [--output OUTPUT]
                         [--repo REPO] [--ref REF]
                         [--base-url BASE_URL] [--model MODEL]
                         [--scan-mode {security,security_and_quality}]
                         [--api-style {chat_completions,responses}]
                         [--max-concurrency MAX_CONCURRENCY]
                         [--log-level {DEBUG,INFO,WARNING,ERROR}]
                         [root]
```

## Notes

- The scanner only trusts issues visible in the current chunk and tells the model to return `{"findings": []}` when there are no meaningful findings.
- Chunking is token-approximate in v1 using a conservative character-based estimate. The code is structured so a tokenizer-aware chunker can replace it later.
- The current client supports OpenAI-compatible `/v1/chat/completions` and `/v1/responses` payload shapes.
- `--repo` currently supports public GitHub repositories only, and requires `git` to be installed and available on `PATH`.
