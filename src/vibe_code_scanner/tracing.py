"""Helpers for live model trace output."""

from __future__ import annotations

from dataclasses import dataclass
import sys
import threading

OPEN_THINK_TAG = "<think>"
CLOSE_THINK_TAG = "</think>"


@dataclass(slots=True)
class _TraceState:
    pending: str = ""
    in_think: bool = False
    header_emitted: bool = False
    trailing_newline: bool = True


class LiveTracePrinter:
    """Show one focused live thinking stream in a readable format."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._states: dict[str, _TraceState] = {}
        self._focused_label: str | None = None
        self._focus_locked = False
        self._notice_emitted = False

    def start(self, label: str) -> None:
        with self._lock:
            self._states.setdefault(label, _TraceState())

    def delta(self, label: str, text: str) -> None:
        if not text:
            return
        with self._lock:
            if self._focus_locked and label != self._focused_label:
                return
            state = self._states.setdefault(label, _TraceState())
            state.pending += text
            self._consume_pending(label, state)

    def notice(self, label: str, message: str) -> None:
        with self._lock:
            if self._notice_emitted:
                return
            if self._focus_locked and label != self._focused_label:
                return
            self._emit_line(f"[trace-live] {message}")
            self._notice_emitted = True

    def finish(self, label: str) -> None:
        with self._lock:
            state = self._states.pop(label, None)
            if state is None:
                return
            if label != self._focused_label:
                return

            if state.in_think and state.pending:
                remainder = state.pending
                close_index = remainder.find(CLOSE_THINK_TAG)
                if close_index >= 0:
                    remainder = remainder[:close_index]
                self._emit_text(state, remainder)

            if state.header_emitted:
                if not state.trailing_newline:
                    self._emit_raw("\n")
                self._emit_line("=== end thinking ===")

    def _consume_pending(self, label: str, state: _TraceState) -> None:
        while True:
            if not state.in_think:
                open_index = state.pending.find(OPEN_THINK_TAG)
                if open_index < 0:
                    state.pending = state.pending[-(len(OPEN_THINK_TAG) - 1) :]
                    return
                state.pending = state.pending[open_index + len(OPEN_THINK_TAG) :]
                state.in_think = True
                if not self._focus_locked:
                    self._focused_label = label
                    self._focus_locked = True
                if label != self._focused_label:
                    state.pending = ""
                    return
                self._emit_header(label, state)
                continue

            close_index = state.pending.find(CLOSE_THINK_TAG)
            if close_index < 0:
                safe_end = max(0, len(state.pending) - (len(CLOSE_THINK_TAG) - 1))
                if safe_end > 0:
                    chunk = state.pending[:safe_end]
                    state.pending = state.pending[safe_end:]
                    self._emit_text(state, chunk)
                return

            if close_index > 0:
                self._emit_text(state, state.pending[:close_index])
            state.pending = state.pending[close_index + len(CLOSE_THINK_TAG) :]
            state.in_think = False

    def _emit_header(self, label: str, state: _TraceState) -> None:
        if state.header_emitted:
            return
        self._emit_line(f"=== thinking: {label} ===")
        state.header_emitted = True
        state.trailing_newline = True

    def _emit_text(self, state: _TraceState, text: str) -> None:
        if not text:
            return
        self._emit_raw(text)
        state.trailing_newline = text.endswith("\n")

    def _emit_line(self, line: str) -> None:
        self._emit_raw(line + "\n")

    def _emit_raw(self, text: str) -> None:
        sys.stdout.write(text)
        sys.stdout.flush()
