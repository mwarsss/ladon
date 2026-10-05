"""
Tools available to the AgentWall AI assistant.

Each tool defines:
- name and descriptive documentation
- parameter schema (JSON Schema format)
- security category (read_private, read_untrusted, write_internal, send_external, financial)
- mock implementation operating on the Environment
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from agentwall.environment import Environment


@dataclass
class ToolDefinition:
    name: str
    description: str
    category: str  # read_private, read_untrusted, write_internal, send_external, financial
    parameters: Dict[str, Any]
    handler: Callable[..., Any]


def tool_read_inbox(env: Environment) -> List[Dict[str, Any]]:
    """List all emails currently in the inbox."""
    return [
        {
            "id": email.id,
            "from": email.from_addr,
            "to": email.to_addr,
            "subject": email.subject,
            "received": email.received,
        }
        for email in env.inbox
    ]


def tool_read_email(env: Environment, id: str) -> Dict[str, Any]:
    """Read the full content of an email by its ID."""
    for email in env.inbox:
        if email.id == str(id):
            return {
                "id": email.id,
                "from": email.from_addr,
                "to": email.to_addr,
                "subject": email.subject,
                "body": email.body,
                "received": email.received,
                "reply_to": email.reply_to,
            }
    return {"error": f"Email with id '{id}' not found"}


def tool_read_file(env: Environment, path: str) -> Dict[str, Any]:
    """Read the content and sensitivity level of a local file."""
    if path in env.files:
        file_item = env.files[path]
        return {
            "path": file_item.path,
            "content": file_item.content,
            "sensitivity": file_item.sensitivity,
        }
    return {"error": f"File '{path}' not found"}


def tool_list_files(env: Environment) -> List[Dict[str, str]]:
    """List all accessible files and their sensitivity levels."""
    return [
        {"path": path, "sensitivity": item.sensitivity}
        for path, item in env.files.items()
    ]


def tool_fetch_url(env: Environment, url: str) -> Dict[str, Any]:
    """Fetch external web page content by URL."""
    if url in env.web_pages:
        return {"url": url, "content": env.web_pages[url]}
    return {"error": f"Page at URL '{url}' not found", "status_code": 404}


def tool_draft_reply(env: Environment, email_id: str, body: str) -> Dict[str, Any]:
    """Draft a response to an email for internal review without sending."""
    record = env.add_draft(email_id=email_id, body=body)
    return {
        "status": "draft_created",
        "email_id": record.email_id,
        "body": record.body,
        "timestamp": record.timestamp,
    }


def tool_send_email(
    env: Environment, to: str, subject: str, body: str
) -> Dict[str, Any]:
    """Send an email to an external or internal address."""
    record = env.add_sent_email(to=to, subject=subject, body=body)
    return {
        "status": "email_sent",
        "to": record.to,
        "subject": record.subject,
        "timestamp": record.timestamp,
    }


def tool_make_payment(
    env: Environment, to: str, amount: float, reference: str
) -> Dict[str, Any]:
    """Execute a bank transfer / payment to a designated account."""
    try:
        amt = float(amount)
    except (ValueError, TypeError):
        return {"error": f"Invalid payment amount: {amount}"}

    # Paying a supplier by name uses the bank account on the supplier list, as an
    # accounts-payable system would. That is exactly why the list itself must be trusted.
    payee = env.get_payee(to)
    account = payee.account if payee and payee.name.lower() == to.strip().lower() else to
    record = env.add_payment(to=account, amount=amt, reference=reference)
    return {
        "status": "payment_executed",
        "to": record.to,
        **({"payee": payee.name} if account != to else {}),
        "amount": record.amount,
        "reference": record.reference,
        "timestamp": record.timestamp,
    }


# Registry of all available tools
ALL_TOOLS: List[ToolDefinition] = [
    ToolDefinition(
        name="read_inbox",
        description="Get a list of all emails in the inbox with sender, subject, and date.",
        category="read_untrusted",
        parameters={
            "type": "object",
            "properties": {},
            "required": [],
        },
        handler=tool_read_inbox,
    ),
    ToolDefinition(
        name="read_email",
        description="Retrieve the full body and details of a specific email by its ID.",
        category="read_untrusted",
        parameters={
            "type": "object",
            "properties": {
                "id": {
                    "type": "string",
                    "description": "The unique ID of the email to read.",
                }
            },
            "required": ["id"],
        },
        handler=tool_read_email,
    ),
    ToolDefinition(
        name="read_file",
        description="Read the contents and sensitivity of a company file by its path.",
        category="read_private",
        parameters={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "The relative or absolute file path to read (e.g. 'finance/q3_payroll.csv').",
                }
            },
            "required": ["path"],
        },
        handler=tool_read_file,
    ),
    ToolDefinition(
        name="list_files",
        description="List all available internal and confidential company files.",
        category="read_private",
        parameters={
            "type": "object",
            "properties": {},
            "required": [],
        },
        handler=tool_list_files,
    ),
    ToolDefinition(
        name="fetch_url",
        description="Fetch content from an external web page or supplier portal.",
        category="read_untrusted",
        parameters={
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "The web URL to fetch.",
                }
            },
            "required": ["url"],
        },
        handler=tool_fetch_url,
    ),
    ToolDefinition(
        name="draft_reply",
        description="Create an internal draft response to a customer or supplier without sending externally.",
        category="write_internal",
        parameters={
            "type": "object",
            "properties": {
                "email_id": {
                    "type": "string",
                    "description": "The ID of the email being replied to.",
                },
                "body": {
                    "type": "string",
                    "description": "The draft response body.",
                },
            },
            "required": ["email_id", "body"],
        },
        handler=tool_draft_reply,
    ),
    ToolDefinition(
        name="send_email",
        description="Send an outgoing email message to an external recipient or internal employee.",
        category="send_external",
        parameters={
            "type": "object",
            "properties": {
                "to": {
                    "type": "string",
                    "description": "Recipient email address.",
                },
                "subject": {
                    "type": "string",
                    "description": "Email subject line.",
                },
                "body": {
                    "type": "string",
                    "description": "Email message body.",
                },
            },
            "required": ["to", "subject", "body"],
        },
        handler=tool_send_email,
    ),
    ToolDefinition(
        name="make_payment",
        description="Authorize and transfer funds to a supplier or payee bank account.",
        category="financial",
        parameters={
            "type": "object",
            "properties": {
                "to": {
                    "type": "string",
                    "description": "Target payee name or bank account number.",
                },
                "amount": {
                    "type": "number",
                    "description": "Payment amount in USD.",
                },
                "reference": {
                    "type": "string",
                    "description": "Invoice number or payment reference.",
                },
            },
            "required": ["to", "amount", "reference"],
        },
        handler=tool_make_payment,
    ),
]

TOOL_MAP: Dict[str, ToolDefinition] = {tool.name: tool for tool in ALL_TOOLS}


def get_tool_metadata(tool_name: str) -> Optional[ToolDefinition]:
    """Retrieve metadata for a tool by name."""
    return TOOL_MAP.get(tool_name)


def get_tool_category(tool_name: str) -> str:
    """Retrieve the security category for a tool."""
    tool = TOOL_MAP.get(tool_name)
    return tool.category if tool else "unknown"


def execute_tool(env: Environment, tool_name: str, arguments: Dict[str, Any]) -> Any:
    """Directly execute a tool against the environment."""
    tool = TOOL_MAP.get(tool_name)
    if not tool:
        return {"error": f"Tool '{tool_name}' is not recognized"}
    try:
        return tool.handler(env, **arguments)
    except Exception as e:
        return {"error": f"Execution error in '{tool_name}': {str(e)}"}


def get_openai_tool_declarations() -> List[Dict[str, Any]]:
    """Return tools formatted for OpenAI-compatible interfaces."""
    declarations = []
    for tool in ALL_TOOLS:
        declarations.append(
            {
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": tool.parameters,
                },
            }
        )
    return declarations
