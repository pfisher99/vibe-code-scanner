"""Token-aware file chunking with configurable overlap."""

from __future__ import annotations

from .models import AppConfig, CodeChunk
from .tokenization import TokenCounter, build_token_counter


def chunk_text(
    text: str,
    config: AppConfig,
    token_counter: TokenCounter | None = None,
) -> list[CodeChunk]:
    lines = text.splitlines(keepends=True)
    if not lines:
        return []

    token_counter = token_counter or build_token_counter(config)
    line_offsets = [0]
    for line in lines:
        line_offsets.append(line_offsets[-1] + len(line))

    span_token_cache: dict[tuple[int, int], int] = {}

    def count_span(start_index: int, end_index: int) -> int:
        if start_index >= end_index:
            return 0
        key = (start_index, end_index)
        if key not in span_token_cache:
            span_text = text[line_offsets[start_index] : line_offsets[end_index]]
            span_token_cache[key] = token_counter.count(span_text)
        return span_token_cache[key]

    raw_chunks: list[dict] = []
    start_index = 0

    while start_index < len(lines):
        end_index = _find_chunk_end(
            start_index,
            len(lines),
            config.chunk_target_tokens,
            count_span,
        )
        token_total = count_span(start_index, end_index)

        raw_chunks.append(
            {
                "start_index": start_index,
                "end_index": end_index,
                "text": text[line_offsets[start_index] : line_offsets[end_index]],
                "estimated_tokens": token_total,
            }
        )

        if end_index >= len(lines):
            break

        start_index = _find_next_start(
            start_index,
            end_index,
            config.chunk_overlap_tokens,
            count_span,
        )

    total_chunks = len(raw_chunks)
    chunks: list[CodeChunk] = []
    previous_end = 0

    for index, raw_chunk in enumerate(raw_chunks, start=1):
        start_line = raw_chunk["start_index"] + 1
        end_line = raw_chunk["end_index"]
        overlap_lines = max(0, previous_end - raw_chunk["start_index"])
        overlap_tokens = (
            count_span(raw_chunk["start_index"], previous_end) if overlap_lines else 0
        )
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


def _find_chunk_end(
    start_index: int,
    total_lines: int,
    chunk_target_tokens: int,
    count_span,
) -> int:
    low = start_index + 1
    high = total_lines
    best_end = start_index + 1

    while low <= high:
        mid = (low + high) // 2
        if count_span(start_index, mid) <= chunk_target_tokens:
            best_end = mid
            low = mid + 1
        else:
            high = mid - 1
    return best_end


def _find_next_start(
    start_index: int,
    end_index: int,
    overlap_target_tokens: int,
    count_span,
) -> int:
    if overlap_target_tokens <= 0:
        return end_index

    candidate = start_index
    low = start_index
    high = end_index - 1

    while low <= high:
        mid = (low + high) // 2
        if count_span(mid, end_index) >= overlap_target_tokens:
            candidate = mid
            low = mid + 1
        else:
            high = mid - 1

    return max(start_index + 1, candidate)
