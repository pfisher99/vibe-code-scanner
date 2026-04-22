# Vibe Code Scanner

Local AI code scanner for poking through a repo with a local OpenAI-compatible model endpoint like vLLM.

This is AI slop generated for fun. It is not trying to cosplay as some serious enterprise security platform. It does, however, actually work, and it is pretty handy if you want to point a local model at a codebase, get structured findings back, and dump the whole thing into reports you can read afterward.

This thing is mostly aimed at local use with a small-ish model on a box with around a 16GB GPU.

## What It Does

- Walks a repo recursively
- Skips common garbage like `.git`, `node_modules`, `dist`, `build`, `.venv`, `__pycache__`, and similar junk
- Skips binary files and oversized files
- Chunks source files by token budget
- Supports chunk overlap
- Sends each chunk to a local model
- Expects strict JSON back
- Deduplicates overlapping findings
- Writes markdown reports plus machine-readable JSON
- Can scan a local folder or clone and scan a public GitHub repo
- Can narrow the scan to a subfolder with `--folder`
- Has a post-scan research pass if you want the model to go back over its own output
- Has trace output so you can see what it is doing when a run gets weird

## Install

```bash
python -m pip install -e .
```

## Quick Start

1. Start your local model server on `http://127.0.0.1:8000`.
2. Edit [`scanner.example.toml`](scanner.example.toml).
3. Run the scanner.

Scan a local folder:

```bash
vibe-code-scanner ../some-repo --config scanner.example.toml
```

Scan only part of a local folder:

```bash
vibe-code-scanner ../some-repo --folder src/server --config scanner.example.toml
```

Scan a public GitHub repo:

```bash
vibe-code-scanner --repo https://github.com/OWASP/NodeGoat --ref master --config scanner.example.toml --scan-mode security --max-concurrency 4
```

Scan only part of a cloned repo:

```bash
vibe-code-scanner --repo https://github.com/OWASP/NodeGoat --folder app --config scanner.example.toml
```

Turn on trace:

```bash
vibe-code-scanner ../some-repo --config scanner.example.toml --trace
```

Run the research pass after scanning:

```bash
vibe-code-scanner ../some-repo --config scanner.example.toml --research
```

Do a small test run against a random subset:

```bash
vibe-code-scanner ../some-repo --config scanner.example.toml --max-files 10
```

Use the big context profile:

```bash
vibe-code-scanner ../some-repo --config scanner.example.toml --max-context
```

## Scan Modes

- `security`: security-focused scan
- `high_security`: only the scary stuff, with hard filtering so only `security` findings rated `high` or `critical` survive
- `security_and_quality`: broader scan that includes security, correctness, suspicious patterns, and maintainability hazards

## Config

Use [`scanner.example.toml`](scanner.example.toml) as the starting point.

The knobs you will probably care about:

- `base_url`
- `model_name`
- `tokenizer_mode`
- `scan_mode`
- `max_concurrent_requests`
- `max_tokens_per_request`
- `chunk_target_tokens`
- `chunk_overlap_tokens`
- `thinking_token_budget_enabled`
- `thinking_token_budget`
- `research`
- `research_max_steps`
- `research_max_tokens_per_request`
- `research_thinking_token_budget`
- `max_context_max_tokens_per_request`
- `max_context_total_context_window_tokens`
- `max_context_research_max_tokens_per_request`
- `max_files`
- `request_timeout_seconds`

The sample config is already set up around a local `Qwen3.5-9B-local` style setup.

## Output

Each run gets its own timestamped folder under `scan-runs`.

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

The stuff you will actually open:

- `index.md`: run summary
- `findings.json`: full machine-readable output
- `files/**/*.md`: per-file reports
- `raw/chunks/*.json`: raw per-chunk artifacts
- `raw/trace/events.jsonl`: trace/debug stream for the run
- `research/final-report.md`: final research report, if enabled

## Trace

`--trace` is the general debug mode.

It will:

- print step-by-step trace lines in the terminal
- show which request slot is handling what
- write a run-level trace stream to `raw/trace/events.jsonl`
- include research loop events too, not just chunk scan events

If a run feels hung, noisy, or just plain cursed, this is the flag you want.

## Research

The first scan pass is from-memory only. No tools.

If you enable `--research`, the scanner does a second pass over its own output. The model can inspect:

- the aggregated findings
- per-file reports
- the original source files for `critical` and `high` findings only
- optional web search results
- fetched reference pages

The research prompt is biased to go deeper only on `critical` and `high` issues. It does not reopen original source files for `medium`, `low`, or `info`-only findings.

Built-in web search can use `duckduckgo`. `searxng` is still there too if you want to point it at your own instance.

Research is useful, but it is still very much AI doing AI things, so treat it like a second-pass assistant, not truth carved into stone.

If it keeps doing useful work but never gets around to finishing, bump `research_max_steps`.

## Prompt Files

If you want to mess with the model behavior, start here:

- [src/vibe_code_scanner/scanner_system_prompt.txt](/c:/Users/sqeak/source/vibe-code-scanner/src/vibe_code_scanner/scanner_system_prompt.txt)
- [src/vibe_code_scanner/scanner_research_prompt.txt](/c:/Users/sqeak/source/vibe-code-scanner/src/vibe_code_scanner/scanner_research_prompt.txt)

## Useful Flags

- `--repo`: clone and scan a public GitHub repo
- `--ref`: branch or tag for `--repo`
- `--folder` or `--start-folder`: scan only a subfolder under the selected source
- `--trace`: turn on trace/debug output
- `--research`: run the final research pass
- `--scan-mode`: pick `security`, `high_security`, or `security_and_quality`
- `--max-files`: random subset for quick tests
- `--max-context`: use the alternate large-context profile from config

## A Few Honest Notes

- This is for fun.
- It is not a substitute for a real security review.
- Small local models still hallucinate, drift, and sometimes dump garbage.
- The scanner tries to keep them on the rails, but they still wander off.
- `--repo` is public GitHub only right now.
- Some runs will be surprisingly useful. Some will be a little dumb. That is just the game here.
