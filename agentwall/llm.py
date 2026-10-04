"""
Unified LLM Provider Interface for AgentWall.

Supports:
1. Google Gemini API via official google-genai SDK (default model: gemini-3.8-flash)
2. Featherless AI fallback via OpenAI-compatible SDK (e.g. Qwen/Qwen2.5-72B-Instruct)
3. Deterministic Replay Provider for offline / camera-ready demos
"""

from __future__ import annotations

import json
import os
import time
import re
from pathlib import Path
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from agentwall.replay import ReplayManager
from agentwall.tools import ALL_TOOLS, ToolDefinition, get_openai_tool_declarations


@dataclass
class ChatMessage:
    role: str  # "system", "user", "assistant", "tool"
    content: Optional[str] = None
    tool_calls: Optional[List[Dict[str, Any]]] = None
    tool_call_id: Optional[str] = None
    name: Optional[str] = None
    # Provider-native message (e.g. Gemini Content with thought signatures), resent unchanged.
    native: Optional[Any] = None


@dataclass
class LLMResponse:
    content: Optional[str] = None
    tool_calls: List[Dict[str, Any]] = field(default_factory=list)
    raw: Optional[Any] = None
    native: Optional[Any] = None


from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env", override=False)


class BaseLLMProvider(ABC):
    """Abstract interface for LLM interaction."""

    @abstractmethod
    def generate(
        self,
        messages: List[ChatMessage],
        tools: Optional[List[ToolDefinition]] = None,
        system_instruction: Optional[str] = None,
    ) -> LLMResponse:
        pass


class ReplayProvider(BaseLLMProvider):
    """Offline replay provider serving recorded interactions."""

    def __init__(self, scenario_name: str):
        self.replay_manager = ReplayManager(scenario_name, mode="replay")

    def generate(
        self,
        messages: List[ChatMessage],
        tools: Optional[List[ToolDefinition]] = None,
        system_instruction: Optional[str] = None,
    ) -> LLMResponse:
        turn = self.replay_manager.get_next_turn()
        if not turn:
            return LLMResponse(
                content="[Replay Completed: No further turns recorded for this scenario]",
                tool_calls=[],
            )
        return LLMResponse(
            content=turn.get("response_content"),
            tool_calls=turn.get("tool_calls", []),
            raw=turn,
        )


class RecordingWrapperProvider(BaseLLMProvider):
    """Wraps an active provider to record every turn for replay caching."""

    def __init__(self, real_provider: BaseLLMProvider, scenario_name: str):
        self.real_provider = real_provider
        self.replay_manager = ReplayManager(scenario_name, mode="record")

    def generate(
        self,
        messages: List[ChatMessage],
        tools: Optional[List[ToolDefinition]] = None,
        system_instruction: Optional[str] = None,
    ) -> LLMResponse:
        response = self.real_provider.generate(messages, tools, system_instruction)
        # Summarize last prompt
        last_msg = messages[-1].content if messages else ""
        self.replay_manager.record_turn(
            prompt_summary=(last_msg or "")[:200],
            response_content=response.content,
            tool_calls=response.tool_calls,
        )
        self.replay_manager.save()
        return response


class GeminiProvider(BaseLLMProvider):
    """Google Gemini provider via the official google-genai SDK."""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        from google import genai
        from google.genai import types

        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            raise ValueError(
                "GEMINI_API_KEY is not set. Please add it to your .env or use replay mode."
            )
        self.model = model or (os.getenv("GEMINI_MODEL") or "gemini-3.8-flash")
        self.client = genai.Client(api_key=self.api_key)

    def _convert_schema_to_gemini(self, schema: Dict[str, Any]) -> Dict[str, Any]:
        """Convert standard JSON Schema types to Gemini Type uppercase strings."""
        type_mapping = {
            "object": "OBJECT",
            "string": "STRING",
            "number": "NUMBER",
            "integer": "INTEGER",
            "boolean": "BOOLEAN",
            "array": "ARRAY",
        }
        res: Dict[str, Any] = {}
        for k, v in schema.items():
            if k == "type" and isinstance(v, str):
                res["type"] = type_mapping.get(v.lower(), "STRING")
            elif k == "properties" and isinstance(v, dict):
                res["properties"] = {
                    pk: self._convert_schema_to_gemini(pv) for pk, pv in v.items()
                }
            elif k == "items" and isinstance(v, dict):
                res["items"] = self._convert_schema_to_gemini(v)
            else:
                res[k] = v
        return res

    def generate(
        self,
        messages: List[ChatMessage],
        tools: Optional[List[ToolDefinition]] = None,
        system_instruction: Optional[str] = None,
    ) -> LLMResponse:
        from google.genai import types

        function_declarations = []
        if tools:
            for tool in tools:
                gemini_params = self._convert_schema_to_gemini(tool.parameters)
                function_declarations.append(
                    types.FunctionDeclaration(
                        name=tool.name,
                        description=tool.description,
                        parameters=gemini_params,
                    )
                )

        gemini_tools = [types.Tool(function_declarations=function_declarations)] if function_declarations else None

        config = types.GenerateContentConfig(
            temperature=0.0,
            system_instruction=system_instruction,
            tools=gemini_tools,
            # AgentWall must see and execute every tool call itself.
            automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
        )

        # Convert messages to Gemini contents structure
        contents: List[Any] = []
        for msg in messages:
            if msg.role == "system":
                continue  # Handled in config.system_instruction
            elif msg.role == "user":
                contents.append(types.Content(role="user", parts=[types.Part.from_text(text=msg.content or "")]))
            elif msg.role == "assistant" and msg.native is not None:
                contents.append(msg.native)
            elif msg.role == "assistant":
                parts = []
                if msg.content:
                    parts.append(types.Part.from_text(text=msg.content))
                if msg.tool_calls:
                    for tc in msg.tool_calls:
                        parts.append(
                            types.Part.from_function_call(
                                name=tc["name"],
                                args=tc.get("arguments", {}),
                            )
                        )
                contents.append(types.Content(role="model", parts=parts))
            elif msg.role == "tool":
                result_payload = msg.content
                if isinstance(result_payload, str):
                    try:
                        result_payload = json.loads(result_payload)
                    except Exception:
                        result_payload = {"result": result_payload}
                part = types.Part.from_function_response(
                    name=msg.name or "unknown_tool",
                    response={"response": result_payload},
                )
                # All results for one model turn go back together in a single message.
                if contents and getattr(contents[-1], "role", None) == "user" and contents[-1].parts and \
                        contents[-1].parts[0].function_response is not None:
                    contents[-1].parts.append(part)
                else:
                    contents.append(types.Content(role="user", parts=[part]))

        response = None
        for attempt in range(8):
            try:
                response = self.client.models.generate_content(
                    model=self.model,
                    contents=contents,
                    config=config,
                )
                break
            except Exception as exc:  # network errors, invalid key, quota
                delay = _rate_limit_delay(exc)
                if delay is None or attempt == 7:
                    raise RuntimeError(
                        f"Gemini API call failed ({type(exc).__name__}: {exc}). "
                        "Check GEMINI_API_KEY and quota, or run with --llm-mode replay."
                    ) from exc
                print(f"[agentwall] Gemini busy or rate-limited; retrying in {delay:.0f}s", file=sys.stderr)
                time.sleep(delay)

        extracted_text = ""
        tool_calls: List[Dict[str, Any]] = []
        native = None

        if response.candidates:
            candidate = response.candidates[0]
            native = candidate.content
            if candidate.content and candidate.content.parts:
                for part in candidate.content.parts:
                    if part.text:
                        extracted_text += part.text
                    if part.function_call:
                        fc = part.function_call
                        tool_calls.append(
                            {
                                "id": f"call_{fc.name}",
                                "name": fc.name,
                                "arguments": dict(fc.args or {}),
                            }
                        )

        return LLMResponse(
            content=extracted_text.strip() if extracted_text else None,
            tool_calls=tool_calls,
            raw=response,
            native=native,
        )


class FeatherlessProvider(BaseLLMProvider):
    """Featherless AI fallback provider via OpenAI client."""

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        from openai import OpenAI

        self.api_key = api_key or os.getenv("FEATHERLESS_API_KEY")
        if not self.api_key:
            raise ValueError(
                "FEATHERLESS_API_KEY is not set. Please add it to your .env or use replay mode."
            )
        self.model = model or (os.getenv("FEATHERLESS_MODEL") or "Qwen/Qwen2.5-72B-Instruct")
        self.client = OpenAI(
            base_url="https://api.featherless.ai/v1",
            api_key=self.api_key,
        )

    def generate(
        self,
        messages: List[ChatMessage],
        tools: Optional[List[ToolDefinition]] = None,
        system_instruction: Optional[str] = None,
    ) -> LLMResponse:
        openai_messages = []
        if system_instruction:
            openai_messages.append({"role": "system", "content": system_instruction})

        for msg in messages:
            m_dict: Dict[str, Any] = {"role": msg.role, "content": msg.content or ""}
            if msg.role == "assistant" and msg.tool_calls:
                m_dict["tool_calls"] = [
                    {
                        "id": tc.get("id", f"call_{i}"),
                        "type": "function",
                        "function": {
                            "name": tc["name"],
                            "arguments": json.dumps(tc.get("arguments", {})),
                        },
                    }
                    for i, tc in enumerate(msg.tool_calls)
                ]
            elif msg.role == "tool":
                m_dict["tool_call_id"] = msg.tool_call_id or "call_0"
            openai_messages.append(m_dict)

        openai_tools = get_openai_tool_declarations() if tools else None

        response = self.client.chat.completions.create(
            model=self.model,
            messages=openai_messages,
            tools=openai_tools,
            temperature=0.0,
        )

        choice = response.choices[0].message
        tool_calls: List[Dict[str, Any]] = []
        if choice.tool_calls:
            for tc in choice.tool_calls:
                args = {}
                try:
                    args = json.loads(tc.function.arguments)
                except Exception:
                    pass
                tool_calls.append(
                    {
                        "id": tc.id,
                        "name": tc.function.name,
                        "arguments": args,
                    }
                )

        return LLMResponse(
            content=choice.content,
            tool_calls=tool_calls,
            raw=response,
        )


def create_llm_provider(
    mode: str = "auto", scenario_name: Optional[str] = None
) -> BaseLLMProvider:
    """Factory creating the appropriate LLM provider based on config and mode."""
    mode = mode.lower()
    forced_replay = (
        mode == "replay"
        or os.getenv("AGENTWALL_MODE", "").lower() == "replay"
    )

    if forced_replay:
        if not scenario_name:
            raise ValueError("Scenario name required for replay mode")
        return ReplayProvider(scenario_name)

    provider_name = os.getenv("LLM_PROVIDER", "gemini").lower()

    if mode == "record":
        if not scenario_name:
            raise ValueError("Scenario name required for record mode")
        if provider_name == "featherless":
            real_provider = FeatherlessProvider()
        else:
            real_provider = GeminiProvider()
        return RecordingWrapperProvider(real_provider, scenario_name)

    # Auto mode: try live provider, fallback to replay if key missing
    if provider_name == "featherless":
        if os.getenv("FEATHERLESS_API_KEY"):
            return FeatherlessProvider()
    else:
        if os.getenv("GEMINI_API_KEY"):
            return GeminiProvider()

    if mode == "live":
        raise ValueError(
            "Live mode needs an API key: set GEMINI_API_KEY (or LLM_PROVIDER=featherless with "
            "FEATHERLESS_API_KEY) in .env, or use --llm-mode replay."
        )

    # Auto mode: fall back to the recorded run, and say so.
    if scenario_name:
        rec_path = ReplayManager.RECORDINGS_DIR / f"{scenario_name}.json"
        if rec_path.exists():
            print(f"[agentwall] No API key set: replaying the recorded run for '{scenario_name}'.", file=sys.stderr)
            return ReplayProvider(scenario_name)

    # If neither key nor replay file exists, provide clear error
    raise ValueError(
        "No API key found (GEMINI_API_KEY / FEATHERLESS_API_KEY) and no replay recording available. "
        "Please set an API key in .env or run with a pre-recorded scenario."
    )


def _rate_limit_delay(exc: Exception) -> Optional[float]:
    """Seconds to wait for a per-minute rate limit (429) or a temporary overload (503), else None."""
    if getattr(exc, "code", None) == 503 or "UNAVAILABLE" in str(exc):
        return 20.0  # model temporarily overloaded on Google's side
    if getattr(exc, "code", None) != 429 and "RESOURCE_EXHAUSTED" not in str(exc):
        return None
    if "PerDay" in str(exc):
        return None  # a daily quota won't recover by waiting
    match = re.search(r"retry in ([0-9.]+)s", str(exc)) or re.search(r"'retryDelay': '([0-9.]+)s'", str(exc))
    return min(float(match.group(1)) + 2, 90) if match else 30.0
