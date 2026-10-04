"""
Taint and Provenance Tracking for AgentWall.

Tracks the lifecycle, trust level, and sensitivity of all data the AI assistant reads,
and determines what data flows into outgoing tool calls (preventing exfiltration
and unauthorized actions driven by untrusted instructions).

Based on the CaMeL (DeepMind) and lethal-trifecta security models:
Do not try to make the model immune to injection; control what data can flow where.
"""

from __future__ import annotations

import datetime
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from rapidfuzz import fuzz

from agentwall.environment import Environment


@dataclass
class ProvenanceLabel:
    source: str  # e.g., "email:msg-101", "file:finance/q3_payroll.csv", "web:url"
    trust: str  # "trusted", "untrusted"
    sensitivity: str  # "public", "internal", "confidential"
    content: str
    created_at: str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )


@dataclass
class TaintFlow:
    label: ProvenanceLabel
    argument_key: str
    match_type: str  # "exact", "fuzzy", "address_match", "account_match"
    similarity: float
    matched_snippet: str


class TaintTracker:
    """Tracks data provenance and analyzes argument data flows."""

    def __init__(self, env: Optional[Environment] = None):
        self.env = env
        self.registry: List[ProvenanceLabel] = []
        self.untrusted_sources_in_context: List[str] = []
        self.untrusted_entities: Set[str] = set()  # emails, bank accounts first seen in untrusted data

    def register(
        self,
        source: str,
        content: str,
        trust: str = "trusted",
        sensitivity: str = "internal",
    ) -> ProvenanceLabel:
        """Register a piece of data with provenance metadata."""
        label = ProvenanceLabel(
            source=source,
            trust=trust.lower(),
            sensitivity=sensitivity.lower(),
            content=content,
        )
        self.registry.append(label)

        if label.trust == "untrusted":
            if source not in self.untrusted_sources_in_context:
                self.untrusted_sources_in_context.append(source)
            self._extract_entities_from_untrusted(content)

        return label

    def _extract_entities_from_untrusted(self, text: str) -> None:
        """Extract email addresses, bank accounts, and payment references from untrusted text."""
        # Email pattern
        email_pattern = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
        for email in re.findall(email_pattern, text):
            self.untrusted_entities.add(email.lower())

        # Account pattern like ACC-12345 or bank numbers
        account_pattern = r"\b(?:ACC-\w+|[0-9]{6,16})\b"
        for acc in re.findall(account_pattern, text):
            self.untrusted_entities.add(acc.upper())

    def track_tool_result(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        output: Any,
        env: Optional[Environment] = None,
    ) -> None:
        """Analyze a tool's output and label all returned data."""
        if not output or isinstance(output, dict) and output.get("error"):
            return

        effective_env = env or self.env

        if tool_name == "read_email":
            email_id = str(arguments.get("id", ""))
            from_addr = output.get("from", "")
            is_internal = effective_env.is_internal_email(from_addr) if effective_env else False
            trust = "trusted" if is_internal else "untrusted"

            body = output.get("body", "")
            subject = output.get("subject", "")
            full_text = f"Subject: {subject}\nFrom: {from_addr}\n\n{body}"

            self.register(
                source=f"email:{email_id}",
                content=full_text,
                trust=trust,
                sensitivity="public" if trust == "untrusted" else "internal",
            )

        elif tool_name == "read_file":
            path = arguments.get("path", "")
            content = output.get("content", "")
            sensitivity = output.get("sensitivity", "internal")
            self.register(
                source=f"file:{path}",
                content=content,
                trust="trusted",
                sensitivity=sensitivity,
            )

        elif tool_name == "fetch_url":
            url = arguments.get("url", "")
            content = output.get("content", "")
            self.register(
                source=f"web:{url}",
                content=content,
                trust="untrusted",
                sensitivity="public",
            )

    def analyze_arguments(self, arguments: Dict[str, Any]) -> List[TaintFlow]:
        """Inspect tool arguments to determine if labelled data flows into them."""
        flows: List[TaintFlow] = []

        for arg_key, arg_val in arguments.items():
            if not isinstance(arg_val, str):
                arg_val_str = str(arg_val)
            else:
                arg_val_str = arg_val

            if not arg_val_str.strip():
                continue

            # 1. Check if argument references an entity that first appeared in untrusted data
            for entity in self.untrusted_entities:
                if entity.lower() in arg_val_str.lower():
                    # Find label where it originated
                    for label in self.registry:
                        if label.trust == "untrusted" and entity.lower() in label.content.lower():
                            flows.append(
                                TaintFlow(
                                    label=label,
                                    argument_key=arg_key,
                                    match_type="untrusted_entity_match",
                                    similarity=100.0,
                                    matched_snippet=entity,
                                )
                            )
                            break

            # 2. Check each labelled value in registry
            for label in self.registry:
                content = label.content.strip()
                if not content:
                    continue

                # Exact substring match (for chunks > 12 chars)
                lines = [line.strip() for line in content.splitlines() if len(line.strip()) >= 12]
                exact_hit = False
                for line in lines:
                    if line in arg_val_str:
                        flows.append(
                            TaintFlow(
                                label=label,
                                argument_key=arg_key,
                                match_type="exact",
                                similarity=100.0,
                                matched_snippet=line[:80],
                            )
                        )
                        exact_hit = True
                        break

                if exact_hit:
                    continue

                # Fuzzy token matching (for paraphrased or reformatted data)
                if len(arg_val_str) > 20 and len(content) > 20:
                    similarity = fuzz.partial_token_set_ratio(arg_val_str, content)
                    if similarity >= 80.0:
                        flows.append(
                            TaintFlow(
                                label=label,
                                argument_key=arg_key,
                                match_type="fuzzy",
                                similarity=similarity,
                                matched_snippet=arg_val_str[:80],
                            )
                        )

        return flows

    def has_confidential_flow(self, arguments: Dict[str, Any]) -> Optional[TaintFlow]:
        """Check if any argument contains data from a confidential source."""
        for flow in self.analyze_arguments(arguments):
            if flow.label.sensitivity == "confidential":
                return flow
        return None

    def has_untrusted_entity_flow(self, arguments: Dict[str, Any]) -> Optional[TaintFlow]:
        """Check if any argument contains an address/account introduced in untrusted content."""
        for flow in self.analyze_arguments(arguments):
            if flow.match_type == "untrusted_entity_match":
                return flow
        return None

    def has_untrusted_instruction_provenance(self) -> bool:
        """Returns True if any untrusted message or page was read into context."""
        return len(self.untrusted_sources_in_context) > 0
