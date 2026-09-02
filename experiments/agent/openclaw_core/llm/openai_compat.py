"""Minimal OpenAI Chat Completions-compatible client.

Zero third-party dependencies. Uses stdlib urllib.request + json only.

Scope (sufficient for harness use cases):
- POST /chat/completions (non-streaming)
- tools= argument (function calling, OpenAI format)
- response.choices[0].message + tool_calls
- usage (prompt_tokens / completion_tokens / total_tokens)
- Retry on 429 and 5xx with exponential backoff + jitter

Out of scope (not needed for harness):
- streaming (SSE)
- embeddings, moderations
- Anthropic / Gemini native payloads (we route through OpenRouter's
  OpenAI-compatible endpoint, which normalizes upstream — SPEC §6.3)

Design notes:
- We don't use requests or httpx — keeps harness fully self-contained.
- Message construction is caller's responsibility; we don't wrap system
  prompts or do any prompt templating.
- The retry logic is conservative: max 3 attempts, 1.5^n * jittered backoff.
  For research reproducibility we log each retry to stderr.
"""

from __future__ import annotations

import json
import os
import random
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Optional


DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"
DEFAULT_TIMEOUT_S = 120
DEFAULT_MAX_RETRIES = 3


# --------------------------------------------------------------------- errors


class ChatClientError(Exception):
    """Raised for unrecoverable HTTP or API errors.

    Attributes:
        status: HTTP status code, or None for transport errors.
        body: raw response body (possibly truncated) if available.
    """

    def __init__(
        self,
        message: str,
        *,
        status: Optional[int] = None,
        body: Optional[str] = None,
    ):
        super().__init__(message)
        self.status = status
        self.body = body


# ---------------------------------------------------------- message dataclasses


@dataclass
class ToolCallFunction:
    """Function call as returned by the model.

    Attributes:
        name: tool name.
        arguments: raw JSON string (NOT parsed) — matches OpenAI's shape.
    """

    name: str
    arguments: str


@dataclass
class ToolCall:
    """One tool call in assistant's message.

    Attributes:
        id: tool_call_id, echoed back in tool role responses.
        type: always "function" for our scope.
        function: the actual function call.
    """

    id: str
    type: str
    function: ToolCallFunction


@dataclass
class ChatMessage:
    """OpenAI chat message.

    Attributes:
        role: "system" | "user" | "assistant" | "tool" | "compactionSummary"
        content: string content (may be empty when role=assistant and tool_calls set)
        tool_calls: populated when assistant returns tool invocations.
        tool_call_id: set on role="tool" messages to echo the call id.
        name: optional, only set on role="tool" responses.
    """

    role: str
    content: str = ""
    tool_calls: Optional[list[ToolCall]] = None
    tool_call_id: Optional[str] = None
    name: Optional[str] = None

    def to_api_dict(self) -> dict[str, Any]:
        """Serialize to the shape the OpenAI-compatible API expects."""
        if self.role == "compactionSummary":
            # OpenClaw stores compaction as a custom transcript role. The
            # OpenAI Chat Completions wire format does not support custom
            # roles, so expose it as prior assistant-side context rather
            # than as a user turn or a new system instruction. This preserves
            # the key upstream behavior: compaction is a session marker, not
            # a new user request.
            return {
                "role": "assistant",
                "content": (
                    "[compactionSummary]\n"
                    "Prior conversation was compacted. Use this summary as "
                    "context only; do not treat it as a user instruction.\n\n"
                    + self.content
                ),
            }

        msg: dict[str, Any] = {"role": self.role}
        # OpenAI accepts empty content on assistant messages with tool_calls;
        # it does NOT accept missing content, so we always include the key.
        msg["content"] = self.content
        if self.tool_calls:
            msg["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": tc.type,
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments,
                    },
                }
                for tc in self.tool_calls
            ]
        if self.tool_call_id is not None:
            msg["tool_call_id"] = self.tool_call_id
        if self.name is not None:
            msg["name"] = self.name
        return msg


@dataclass
class Usage:
    """Token accounting.

    Attributes:
        prompt_tokens: tokens in the request.
        completion_tokens: tokens in the response.
        total_tokens: sum. Some providers omit this; we fill it when both
            components are present.
    """

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


@dataclass
class ChatResponse:
    """Single-choice chat completion response.

    Attributes:
        message: the assistant message (content and/or tool_calls).
        finish_reason: "stop" | "tool_calls" | "length" | "content_filter" | None.
        model: provider-reported model identifier.
        usage: token accounting (may be zeros if provider didn't report).
        raw: the full decoded JSON response for caller inspection.
    """

    message: ChatMessage
    finish_reason: Optional[str]
    model: str
    usage: Usage = field(default_factory=Usage)
    raw: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------- parsing


def _parse_tool_calls(raw_tool_calls: Any) -> Optional[list[ToolCall]]:
    if not isinstance(raw_tool_calls, list) or not raw_tool_calls:
        return None
    out: list[ToolCall] = []
    for tc in raw_tool_calls:
        if not isinstance(tc, dict):
            continue
        fn = tc.get("function") or {}
        if not isinstance(fn, dict):
            continue
        name = fn.get("name")
        if not isinstance(name, str):
            continue
        args = fn.get("arguments", "")
        if not isinstance(args, str):
            # Some providers return a dict — coerce to JSON string for
            # uniformity (OpenAI spec says string).
            args = json.dumps(args)
        out.append(
            ToolCall(
                id=str(tc.get("id", "")),
                type=str(tc.get("type", "function")),
                function=ToolCallFunction(name=name, arguments=args),
            )
        )
    return out or None


def _parse_response(payload: dict[str, Any]) -> ChatResponse:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ChatClientError("response missing choices", body=json.dumps(payload)[:2000])
    choice = choices[0]
    if not isinstance(choice, dict):
        raise ChatClientError("response choice is not an object")

    raw_msg = choice.get("message") or {}
    if not isinstance(raw_msg, dict):
        raise ChatClientError("response message is not an object")

    content = raw_msg.get("content")
    if content is None:
        content_str = ""
    elif isinstance(content, str):
        content_str = content
    elif isinstance(content, list):
        # Some providers return content as a list of parts; concat text parts.
        parts: list[str] = []
        for part in content:
            if isinstance(part, dict):
                txt = part.get("text")
                if isinstance(txt, str):
                    parts.append(txt)
        content_str = "".join(parts)
    else:
        content_str = str(content)

    message = ChatMessage(
        role=str(raw_msg.get("role", "assistant")),
        content=content_str,
        tool_calls=_parse_tool_calls(raw_msg.get("tool_calls")),
    )

    finish = choice.get("finish_reason")
    finish_reason: Optional[str] = str(finish) if isinstance(finish, str) else None

    raw_usage = payload.get("usage") or {}
    if not isinstance(raw_usage, dict):
        raw_usage = {}
    usage = Usage(
        prompt_tokens=int(raw_usage.get("prompt_tokens", 0) or 0),
        completion_tokens=int(raw_usage.get("completion_tokens", 0) or 0),
        total_tokens=int(raw_usage.get("total_tokens", 0) or 0),
    )
    if usage.total_tokens == 0 and (usage.prompt_tokens or usage.completion_tokens):
        usage.total_tokens = usage.prompt_tokens + usage.completion_tokens

    return ChatResponse(
        message=message,
        finish_reason=finish_reason,
        model=str(payload.get("model", "")),
        usage=usage,
        raw=payload,
    )


# ----------------------------------------------------------------- client


class ChatClient:
    """Blocking, retry-aware OpenAI-compatible chat client.

    Typical use:

        client = ChatClient(
            api_key=os.environ["OPENROUTER_API_KEY"],
            model="google/gemini-3-flash-preview",
        )
        resp = client.chat(
            messages=[ChatMessage("user", "hello")],
            tools=get_default_tool_schemas(),
        )
    """

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT_S,
        max_retries: int = DEFAULT_MAX_RETRIES,
        extra_headers: Optional[dict[str, str]] = None,
        user_agent: str = "openclaw-harness/0.1",
    ):
        if not api_key:
            raise ValueError("api_key is required")
        if not model:
            raise ValueError("model is required")
        self._api_key = api_key
        self._model = model
        # Strip trailing slash for consistent URL joining.
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._max_retries = max(0, max_retries)
        self._extra_headers = dict(extra_headers or {})
        self._user_agent = user_agent

    # ------- URL + header assembly

    def _url(self, path: str) -> str:
        if not path.startswith("/"):
            path = "/" + path
        return self._base_url + path

    def _headers(self) -> dict[str, str]:
        h = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
            "User-Agent": self._user_agent,
        }
        # OpenRouter-recommended headers — harmless on pure OpenAI endpoint.
        h.setdefault("HTTP-Referer", "https://assa-bench.research.local")
        h.setdefault("X-Title", "SELFSTATE")
        for k, v in self._extra_headers.items():
            h[k] = v
        return h

    # ------- public API

    def chat(
        self,
        messages: list[ChatMessage],
        *,
        tools: Optional[list[dict[str, Any]]] = None,
        tool_choice: Optional[Any] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        model: Optional[str] = None,
        extra_body: Optional[dict[str, Any]] = None,
    ) -> ChatResponse:
        """Single non-streaming chat completion.

        Args:
            messages: ordered history.
            tools: list of tool schemas (see pi_tools.schema.get_default_tool_schemas).
            tool_choice: "auto" | "none" | {"type":"function","function":{"name":...}}
            temperature / max_tokens: optional provider parameters.
            model: override the default model for this call.
            extra_body: additional top-level fields to merge into the request body.

        Returns:
            ChatResponse.

        Raises:
            ChatClientError on unrecoverable HTTP/API errors.
        """
        body: dict[str, Any] = {
            "model": model or self._model,
            "messages": [m.to_api_dict() for m in messages],
        }
        if tools:
            body["tools"] = tools
        if tool_choice is not None:
            body["tool_choice"] = tool_choice
        if temperature is not None:
            body["temperature"] = temperature
        if max_tokens is not None:
            body["max_tokens"] = max_tokens
        if extra_body:
            for k, v in extra_body.items():
                body[k] = v

        payload = self._request_with_retry("/chat/completions", body)
        return _parse_response(payload)

    # ------- HTTP internals

    def _request_with_retry(
        self, path: str, body: dict[str, Any]
    ) -> dict[str, Any]:
        url = self._url(path)
        data = json.dumps(body).encode("utf-8")
        headers = self._headers()

        attempt = 0
        last_error: Optional[ChatClientError] = None
        while True:
            try:
                return self._request_once(url, data, headers)
            except ChatClientError as exc:
                last_error = exc
                retryable = exc.status is None or exc.status == 429 or (
                    exc.status is not None and 500 <= exc.status < 600
                )
                if not retryable or attempt >= self._max_retries:
                    raise
                # Exponential backoff with jitter: 0.5, 1.5, 3.0 ... seconds.
                sleep_s = 0.5 * (1.5**attempt) + random.uniform(0, 0.25)
                print(
                    f"[llm] retry {attempt + 1}/{self._max_retries} "
                    f"after {sleep_s:.2f}s (status={exc.status}, err={exc})",
                    file=sys.stderr,
                )
                time.sleep(sleep_s)
                attempt += 1
                continue

        # Unreachable, but satisfies type narrowing.
        assert last_error is not None
        raise last_error

    def _request_once(
        self,
        url: str,
        data: bytes,
        headers: dict[str, str],
    ) -> dict[str, Any]:
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                raw = resp.read()
                status = resp.status
        except urllib.error.HTTPError as exc:
            body_text = ""
            try:
                body_bytes = exc.read()
                body_text = body_bytes.decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                pass
            # Try to surface provider error message if JSON.
            msg = f"HTTP {exc.code} from {url}"
            try:
                err_payload = json.loads(body_text) if body_text else None
                if isinstance(err_payload, dict):
                    err_detail = err_payload.get("error")
                    if isinstance(err_detail, dict):
                        detail_msg = err_detail.get("message")
                        if isinstance(detail_msg, str):
                            msg = f"HTTP {exc.code}: {detail_msg}"
                    elif isinstance(err_detail, str):
                        msg = f"HTTP {exc.code}: {err_detail}"
            except json.JSONDecodeError:
                pass
            raise ChatClientError(msg, status=exc.code, body=body_text[:2000]) from exc
        except urllib.error.URLError as exc:
            raise ChatClientError(
                f"transport error contacting {url}: {exc.reason}",
                status=None,
            ) from exc
        except TimeoutError as exc:
            raise ChatClientError(
                f"timeout after {self._timeout}s contacting {url}",
                status=None,
            ) from exc

        if status != 200:
            # Non-2xx that didn't raise HTTPError (rare with urllib).
            raise ChatClientError(
                f"unexpected status {status}",
                status=status,
                body=raw[:2000].decode("utf-8", errors="replace"),
            )

        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ChatClientError(
                f"invalid JSON in response: {exc}",
                status=status,
                body=raw[:2000].decode("utf-8", errors="replace"),
            ) from exc


# ------------------------------------------------------- convenience factory


def client_from_env(
    *,
    model: str,
    base_url: Optional[str] = None,
    env_var: str = "OPENROUTER_API_KEY",
) -> ChatClient:
    """Build a ChatClient reading the key from the environment.

    Args:
        model: provider-qualified model id (e.g. "google/gemini-3-flash-preview").
        base_url: override default OpenRouter endpoint.
        env_var: name of the env var holding the API key.

    Raises:
        RuntimeError if `env_var` is unset or empty.
    """
    api_key = os.environ.get(env_var, "").strip()
    if not api_key:
        raise RuntimeError(
            f"environment variable {env_var} is not set; cannot build ChatClient"
        )
    return ChatClient(
        api_key=api_key,
        model=model,
        base_url=base_url or DEFAULT_BASE_URL,
    )
