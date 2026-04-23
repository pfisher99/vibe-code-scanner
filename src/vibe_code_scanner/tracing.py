"""Trace helpers for console progress output and optional run-level event capture."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CONSOLE_RESEARCH_EVENTS = {
    "research_step_started",
    "research_action_parsed",
    "research_feedback_injected",
    "research_tool_executed",
    "research_step_failed",
    "research_finished",
}


class TraceRecorder:
    def __init__(self, run_dir: Path, *, enabled: bool, logger: logging.Logger, max_slots: int) -> None:
        self._enabled = enabled
        self._logger = logger
        self._write_lock = asyncio.Lock()
        self._slot_queue: asyncio.Queue[int] | None = None
        self.events_path: Path | None = None
        if not enabled:
            return

        trace_dir = run_dir / "raw" / "trace"
        trace_dir.mkdir(parents=True, exist_ok=True)
        self.events_path = trace_dir / "events.jsonl"
        self.events_path.write_text("", encoding="utf-8")
        self._slot_queue = asyncio.Queue()
        for slot_id in range(1, max_slots + 1):
            self._slot_queue.put_nowait(slot_id)

    @property
    def enabled(self) -> bool:
        return self._enabled

    async def acquire_slot(self, label: str) -> int | None:
        if not self._enabled or self._slot_queue is None:
            return None
        slot_id = await self._slot_queue.get()
        await self.record("slot_acquired", label=label, slot_id=slot_id)
        return slot_id

    async def release_slot(self, slot_id: int | None, label: str) -> None:
        if not self._enabled or self._slot_queue is None or slot_id is None:
            return
        await self.record("slot_released", label=label, slot_id=slot_id)
        self._slot_queue.put_nowait(slot_id)

    async def record(self, event: str, **details: Any) -> None:
        if _should_log_to_console(event):
            self._logger.info("[%s] %s", ("trace" if self._enabled else "progress"), _format_trace_log(event, details))
        if not self._enabled or self.events_path is None:
            return
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **details,
        }
        async with self._write_lock:
            with self.events_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(payload, ensure_ascii=True) + "\n")


def append_trace_step(trace_data, step: str, **details: Any) -> None:
    if trace_data is None:
        return
    trace_data.steps.append(
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "step": step,
            **details,
        }
    )


def _format_trace_log(event: str, details: dict[str, Any]) -> str:
    slot_prefix = f"slot={details['slot_id']} " if "slot_id" in details and details["slot_id"] is not None else ""
    label = str(details.get("label", "")).strip()
    extras = []
    for key in (
        "file_path",
        "chunk_index",
        "total_chunks",
        "line_start",
        "line_end",
        "estimated_tokens",
        "file_count",
        "skipped_count",
        "scanned_files",
        "error_count",
        "status",
        "finding_count",
        "duration_ms",
        "step_index",
        "action",
        "argument",
        "query",
        "url",
        "error",
    ):
        value = details.get(key)
        if value not in (None, "", []):
            extras.append(f"{key}={value}")
    suffix = f" ({', '.join(extras)})" if extras else ""
    return f"{slot_prefix}{event} {label}".strip() + suffix


def _should_log_to_console(event: str) -> bool:
    return event in CONSOLE_RESEARCH_EVENTS
