# Vibe Code Scanner

This is a local AI code scanner for messing around with source trees using a local OpenAI-compatible model endpoint like vLLM.

Also, to be extremely clear: this is AI slop generated for fun. It is not pretending to be some polished enterprise security product. That said, it does actually work, and it is pretty decent for poking through a repo, chunking files, asking a local model for structured findings, and dumping the results into reports you can read later.

The whole thing is aimed at local use on a machine with a roughly 16GB GPU and a small-ish model, not a hosted SaaS setup.

TOML is used for config because Python 3.11 already ships `tomllib`, which keeps the project dependency-light and easy to tweak.

## What It Does

- Walks a repo recursively
- Skips common junk like `.git`, `node_modules`, `dist`, `build`, `bin`, `obj`, `.venv`, `__pycache__`, and similar folders
- Skips binary files and oversized files
- Chunks source files by token budget
- Supports chunk overlap
- Sends each chunk to a local model
- Expects strict JSON back
- Deduplicates overlapping findings
- Writes markdown reports plus machine-readable JSON
- Can clone and scan a public GitHub repo directly
- Has a post-scan research pass if you want the model to go back over its own output
- Has trace/debug output so you can actually see what the scanner is doing

## Install

```bash
python -m pip install -e .
```

## Quick Start

1. Start your local model server on `http://127.0.0.1:8000`.
2. Copy or edit [`scanner.example.toml`](scanner.example.toml).
3. Run the scanner.

Scan a local repo:

```bash
vibe-code-scanner ../some-repo --config scanner.example.toml
```

Scan a public GitHub repo:

```bash
vibe-code-scanner --repo https://github.com/OWASP/NodeGoat --ref master --config scanner.example.toml --scan-mode security --max-concurrency 4
```

Turn on trace/debug output:

```bash
vibe-code-scanner ../some-repo --config scanner.example.toml --trace
```

Run the post-scan research pass:

```bash
vibe-code-scanner ../some-repo --config scanner.example.toml --research
```

Use the built-in web search path during research:

```bash
vibe-code-scanner ../some-repo --config scanner.example.toml --research --search-backend duckduckgo
```

Run only a random subset of files for a quick test:

```bash
vibe-code-scanner ../some-repo --config scanner.example.toml --max-files 10
```

Use the alternate big-window profile from config:

```bash
vibe-code-scanner ../some-repo --config scanner.example.toml --max-context
```

## The Current Vibe

The sample config is tuned around a local `Qwen3.5-9B-local` style setup.

Normal mode in the sample config is basically:

- `max_tokens_per_request = 16384`
- `chunk_target_tokens = 32768`
- `thinking_token_budget = 8192`
- `max_concurrent_requests = 4`

There is also an optional `--max-context` mode now. That pulls a separate token profile from config and rewrites the runtime settings.

In the sample config that means:

- total context window: `262144`
- output tokens: `81920`
- input chunk target: `180224`
- thinking budget: disabled

So yes, the scanner does the math for you instead of making you fiddle with it every run.

## Important Config Knobs

See [`scanner.example.toml`](scanner.example.toml).

The ones that matter most:

- `base_url`: where your local OpenAI-compatible endpoint lives
- `model_name`: model id sent to the endpoint
- `tokenizer_mode`: `vllm`, `auto`, or `heuristic`
- `scan_mode`: `security` or `security_and_quality`
- `max_concurrent_requests`: how many requests stay in flight
- `max_tokens_per_request`: output token cap for normal scan mode
- `chunk_target_tokens`: input chunk size target
- `chunk_overlap_tokens`: overlap between adjacent chunks
- `thinking_token_budget_enabled`: whether to send `extra_body.thinking_token_budget`
- `thinking_token_budget`: normal scan reasoning budget
- `research`: whether to run the final research pass
- `research_max_tokens_per_request`: research-only output cap
- `research_thinking_token_budget`: research-only reasoning budget
- `max_context_max_tokens_per_request`: alternate output budget used by `--max-context`
- `max_context_total_context_window_tokens`: alternate total window used by `--max-context`
- `max_context_research_max_tokens_per_request`: optional research output cap when `--max-context` is on
- `max_files`: random testing limit
- `request_timeout_seconds`: per-request timeout

## Output

Each run gets its own timestamped folder under `export_dir`.

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
      trace/
        events.jsonl
      research/
        final-report.json
```

The useful bits are:

- `index.md`: run summary
- `findings.json`: full machine-readable output
- `files/**/*.md`: per-file markdown reports
- `raw/chunks/*.json`: raw per-chunk results
- `raw/trace/events.jsonl`: trace/debug stream for the run
- `research/final-report.md`: final research report, if enabled

## Trace Mode

`--trace` is the general debug mode now.

It does three things:

- prints step-by-step trace lines in the terminal
- tracks which concurrent request slot is doing what
- stores richer trace metadata in chunk artifacts and `raw/trace/events.jsonl`

So if a run feels stuck, weird, or noisy, this is the mode you want.

## Research Mode

The first scan pass is from-memory only. No tools.

If you enable `--research`, the scanner then does a second pass where the model can inspect:

- the aggregated findings
- per-file reports
- optional web search results
- fetched reference pages

Right now the built-in no-extra-dependency search path is `duckduckgo`. `searxng` is still supported if you want to point at your own instance.

Research is useful, but it is still very much “AI doing AI things,” so treat it like a second-pass assistant, not ground truth.

## A Few Honest Notes

- This is for fun. It is not a substitute for a real security review.
- Small local models will still hallucinate, drift, or output garbage sometimes.
- The scanner tries hard to force strict JSON and recover from messy outputs, but the model can still be annoying.
- `thinking_token_budget` is not standard OpenAI API behavior. It only works when the endpoint supports it.
- `--repo` is public GitHub only right now and depends on `git` being installed.
- The built-in web search path is intentionally simple.
- Broad file scanning is a tradeoff. The sample config is tuned to avoid a bunch of low-value junk.

## CLI

```text
usage: vibe-code-scanner [-h] [--config CONFIG] [--output OUTPUT]
                         [--repo REPO] [--ref REF]
                         [--base-url BASE_URL] [--model MODEL]
                         [--max-context] [--trace]
                         [--research] [--search-backend {none,searxng,duckduckgo}]
                         [--search-base-url SEARCH_BASE_URL]
                         [--scan-mode {security,security_and_quality}]
                         [--api-style {chat_completions,responses}]
                         [--max-concurrency MAX_CONCURRENCY]
                         [--max-files MAX_FILES]
                         [--log-level {DEBUG,INFO,WARNING,ERROR}]
                         [root]
```

## Prompt Files

The scanner prompt lives here:

- [src/vibe_code_scanner/scanner_system_prompt.txt](/c:/Users/sqeak/source/vibe-code-scanner/src/vibe_code_scanner/scanner_system_prompt.txt)

The post-scan research prompt lives here:

- [src/vibe_code_scanner/scanner_research_prompt.txt](/c:/Users/sqeak/source/vibe-code-scanner/src/vibe_code_scanner/scanner_research_prompt.txt)

So if you want to keep tuning the model behavior, those are the first files to mess with.
