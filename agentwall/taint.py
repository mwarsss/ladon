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
from functools import lru_cache
from urllib.parse import unquote_plus
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


from agentwall.environment import Environment


_TOKEN_RE = re.compile(r"[a-z0-9]+")
_STOPWORDS = {
    "the", "and", "for", "with", "that", "this", "from", "your", "you", "our", "are",
    "was", "were", "will", "have", "has", "had", "not", "but", "all", "any", "can",
    "into", "onto", "about", "please", "thank", "thanks", "dear", "regards", "hello",
    "kind", "best", "would", "could", "should", "there", "their", "they", "them",
    "what", "when", "where", "which", "while", "been", "being", "also", "just",
}


def _tokens(text: str) -> List[str]:
    return _TOKEN_RE.findall(unquote_plus(text).lower())


def _shingles(tokens: List[str], n: int = 3) -> Set[str]:
    out = set()
    for i in range(len(tokens) - n + 1):
        window = tokens[i : i + n]
        if any(len(t) >= 4 and t not in _STOPWORDS for t in window):
            out.add(" ".join(window))
    return out


@dataclass(frozen=True)
class _Fingerprint:
    lines: tuple
    shingles: frozenset
    distinctive: frozenset
    terms: frozenset


@lru_cache(maxsize=512)
def _fingerprint(content: str) -> Optional[_Fingerprint]:
    if not content.strip():
        return None
    lines = []
    for raw in content.splitlines():
        norm = " ".join(_tokens(raw))
        if len(norm) >= 12:
            lines.append(norm)
    tokens = _tokens(content)
    return _Fingerprint(
        lines=tuple(lines),
        shingles=frozenset(_shingles(tokens)),
        distinctive=frozenset(t for t in tokens if len(t) >= 4 and any(c.isdigit() for c in t)),
        terms=frozenset(t for t in tokens if len(t) >= 4 and t not in _STOPWORDS),
    )


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
            arg_tokens = _tokens(arg_val_str)
            arg_norm = " ".join(arg_tokens)
            arg_shingles = _shingles(arg_tokens)
            arg_token_set = set(arg_tokens)
            for label in self.registry:
                fp = _fingerprint(label.content)
                if fp is None:
                    continue

                exact = next((line for line in fp.lines if line in arg_norm), None)
                if exact:
                    flows.append(
                        TaintFlow(
                            label=label,
                            argument_key=arg_key,
                            match_type="exact",
                            similarity=100.0,
                            matched_snippet=exact[:80],
                        )
                    )
                    continue

                # Fragments: a partial row or reformatted excerpt still carries
                # at least two pieces of evidence: distinctive values or phrases.
                shared_ids = fp.distinctive & arg_token_set
                shared_shingles = fp.shingles & arg_shingles
                if len(shared_ids) + len(shared_shingles) >= 2:
                    evidence = sorted(shared_ids) or sorted(shared_shingles)
                    flows.append(
                        TaintFlow(
                            label=label,
                            argument_key=arg_key,
                            match_type="fragment",
                            similarity=100.0,
                            matched_snippet=", ".join(evidence)[:80],
                        )
                    )
                    continue

                # Paraphrase: most of the document's key terms reappear.
                shared_terms = fp.terms & arg_token_set
                if len(shared_terms) >= 4 and len(shared_terms) >= 0.5 * len(fp.terms):
                    flows.append(
                        TaintFlow(
                            label=label,
                            argument_key=arg_key,
                            match_type="fuzzy",
                            similarity=round(100.0 * len(shared_terms) / len(fp.terms), 1),
                            matched_snippet=", ".join(sorted(shared_terms))[:80],
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
