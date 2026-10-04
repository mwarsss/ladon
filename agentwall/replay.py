"""
Deterministic Record and Replay engine for LLM interactions.

Enables 100% offline, zero-latency, rate-limit-immune demos and automated tests
by recording Gemini/Featherless interactions to JSON files and replaying them accurately.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class ReplayTurn:
    step: int
    prompt_summary: str
    response_content: Optional[str]
    tool_calls: Optional[List[Dict[str, Any]]]


class ReplayManager:
    """Manages recording and replaying model turns for a specific scenario."""

    RECORDINGS_DIR = Path(__file__).resolve().parent.parent / "scenarios" / "recordings"

    def __init__(self, scenario_name: str, mode: str = "replay"):
        self.scenario_name = scenario_name
        self.mode = mode.lower()  # "record", "replay", "live"
        self.file_path = self.RECORDINGS_DIR / f"{scenario_name}.json"
        self.turns: List[Dict[str, Any]] = []
        self.current_step = 0

        if self.mode == "replay":
            self._load()

    def _load(self) -> None:
        """Load recorded turns from JSON file."""
        if not self.file_path.exists():
            raise FileNotFoundError(
                f"No replay recording found at '{self.file_path}'. "
                f"Run with RECORD mode first or check scenarios/recordings."
            )
        with open(self.file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            self.turns = data.get("turns", [])

    def record_turn(
        self,
        prompt_summary: str,
        response_content: Optional[str],
        tool_calls: Optional[List[Dict[str, Any]]],
    ) -> None:
        """Record a completed turn."""
        turn = {
            "step": self.current_step,
            "prompt_summary": prompt_summary,
            "response_content": response_content,
            "tool_calls": tool_calls or [],
        }
        self.turns.append(turn)
        self.current_step += 1

    def get_next_turn(self) -> Optional[Dict[str, Any]]:
        """Retrieve the next recorded turn in replay mode."""
        if self.current_step < len(self.turns):
            turn = self.turns[self.current_step]
            self.current_step += 1
            return turn
        return None

    def save(self) -> None:
        """Save recorded turns to disk."""
        self.RECORDINGS_DIR.mkdir(parents=True, exist_ok=True)
        data = {
            "scenario": self.scenario_name,
            "total_turns": len(self.turns),
            "turns": self.turns,
        }
        with open(self.file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def reset(self) -> None:
        """Reset turn pointer for replay."""
        self.current_step = 0
