"""LLM client layer — minimal OpenAI Chat Completions-compatible client.

All traffic routes through OpenRouter's OpenAI-compatible endpoint (user
decision 2026-04-22). This package has zero third-party dependencies — HTTP
via stdlib urllib.request, JSON via stdlib json.

Public surface:
- ChatClient: blocking client with .chat(messages, tools=...) -> ChatResponse
- ChatMessage / ToolCall / ChatResponse dataclasses
- ChatClientError for HTTP / API errors
"""

from .openai_compat import (
    ChatClient,
    ChatClientError,
    ChatMessage,
    ChatResponse,
    ToolCall,
    ToolCallFunction,
    Usage,
    client_from_env,
)

__all__ = [
    "ChatClient",
    "ChatClientError",
    "ChatMessage",
    "ChatResponse",
    "ToolCall",
    "ToolCallFunction",
    "Usage",
    "client_from_env",
]
