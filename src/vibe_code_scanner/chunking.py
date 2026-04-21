"""Token-approximate file chunking with configurable overlap."""

from __future__ import annotations

import math

from .models import AppConfig, CodeChunk


def estimate_tokens(text: str) -> int:
    """Conservative character-based estimate until a tokenizer is plugged in."""

    if not text:
        return 0
    return max(1, math.ceil(len(text) / 3.5))


def chunk_text(text: str, config: AppConfig) -> list[CodeChunk]:
    lines = text.splitlines(keepends=True)
    if not lines:
        return []

    line_tokens = [estimate_tokens(line) for line in lines]
    raw_chunks: list[dict] = []
    start_index = 0

    while start_index < len(lines):
        end_index = start_index
        token_total = 0

        while end_index < len(lines):
            next_tokens = line_tokens[end_index]
            if end_index > start_index and token_total + next_tokens > config.chunk_target_tokens:
                break
            token_total += next_tokens
            end_index += 1

        if end_index == start_index:
            token_total = line_tokens[start_index]
            end_index += 1

        raw_chunks.append(
            {
                "start_index": start_index,
                "end_index": end_index,
                "text": "".join(lines[start_index:end_index]),
                "estimated_tokens": token_total,
            }
        )

        if end_index >= len(lines):
            break

        overlap_tokens = 0
        overlap_lines = 0
        rewind_index = end_index - 1
        while rewind_index >= start_index and overlap_tokens < config.chunk_overlap_tokens:
            overlap_tokens += line_tokens[rewind_index]
            overlap_lines += 1
            rewind_index -= 1

        next_start = max(start_index + 1, end_index - overlap_lines)
        start_index = next_start

    total_chunks = len(raw_chunks)
    chunks: list[CodeChunk] = []
    previous_end = 0

    for index, raw_chunk in enumerate(raw_chunks, start=1):
        start_line = raw_chunk["start_index"] + 1
        end_line = raw_chunk["end_index"]
        overlap_lines = max(0, previous_end - raw_chunk["start_index"])
        overlap_tokens = sum(line_tokens[raw_chunk["start_index"] : previous_end]) if overlap_lines else 0
        chunks.append(
            CodeChunk(
                chunk_index=index,
                total_chunks=total_chunks,
                start_line=start_line,
                end_line=end_line,
                text=raw_chunk["text"],
                estimated_tokens=raw_chunk["estimated_tokens"],
                overlap_from_previous_tokens=overlap_tokens,
                overlap_from_previous_lines=overlap_lines,
            )
        )
        previous_end = raw_chunk["end_index"]
    return chunks
