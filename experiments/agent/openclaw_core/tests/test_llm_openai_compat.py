"""Unit tests for openclaw_core.llm.openai_compat.

All tests are offline — no real network calls. We mock urllib.request.urlopen
to exercise the client with deterministic HTTP responses.

Coverage:
- ChatMessage.to_api_dict() shape
- _parse_response on success, missing choices, list-content format
- tool_calls round-trip (parse)
- ChatClient builds correct URL/headers/body
- Retry on 429 and 5xx; no retry on 4xx
- ChatClientError carries status and body
"""

from __future__ import annotations

import io
import json
import unittest
import urllib.error
from unittest import mock

from openclaw_core.llm.openai_compat import (
    ChatClient,
    ChatClientError,
    ChatMessage,
    ToolCall,
    ToolCallFunction,
    _parse_response,
    client_from_env,
)


def _make_http_response(body_obj: dict, status: int = 200) -> mock.MagicMock:
    """Return a urlopen-compatible mock yielding the given JSON body."""
    body = json.dumps(body_obj).encode("utf-8")
    resp = mock.MagicMock()
    resp.read.return_value = body
    resp.status = status
    # Context-manager protocol.
    resp.__enter__ = mock.MagicMock(return_value=resp)
    resp.__exit__ = mock.MagicMock(return_value=False)
    return resp


def _make_http_error(status: int, body_obj: dict) -> urllib.error.HTTPError:
    body = json.dumps(body_obj).encode("utf-8")
    fp = io.BytesIO(body)
    return urllib.error.HTTPError(
        url="http://test",
        code=status,
        msg="err",
        hdrs={},  # type: ignore[arg-type]
        fp=fp,
    )


class ChatMessageTests(unittest.TestCase):
    def test_user_message_shape(self) -> None:
        m = ChatMessage(role="user", content="hi")
        self.assertEqual(m.to_api_dict(), {"role": "user", "content": "hi"})

    def test_compaction_summary_is_not_serialized_as_user(self) -> None:
        m = ChatMessage(role="compactionSummary", content="old task summary")
        d = m.to_api_dict()
        self.assertEqual(d["role"], "assistant")
        self.assertIn("old task summary", d["content"])
        self.assertIn("context only", d["content"])
        self.assertNotIn("Continue from where", d["content"])

    def test_tool_call_round_trip(self) -> None:
        m = ChatMessage(
            role="assistant",
            content="",
            tool_calls=[
                ToolCall(
                    id="tc_1",
                    type="function",
                    function=ToolCallFunction(
                        name="read", arguments='{"path":"a.txt"}'
                    ),
                )
            ],
        )
        d = m.to_api_dict()
        self.assertEqual(d["role"], "assistant")
        self.assertEqual(d["content"], "")
        self.assertEqual(len(d["tool_calls"]), 1)
        self.assertEqual(d["tool_calls"][0]["function"]["name"], "read")
        self.assertEqual(
            d["tool_calls"][0]["function"]["arguments"], '{"path":"a.txt"}'
        )

    def test_tool_response_message(self) -> None:
        m = ChatMessage(
            role="tool", content='{"ok":true}', tool_call_id="tc_1", name="read"
        )
        d = m.to_api_dict()
        self.assertEqual(d["tool_call_id"], "tc_1")
        self.assertEqual(d["name"], "read")


class ParseResponseTests(unittest.TestCase):
    def test_parses_plain_text_response(self) -> None:
        payload = {
            "model": "x/y",
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": "hello"},
                }
            ],
            "usage": {"prompt_tokens": 7, "completion_tokens": 3},
        }
        resp = _parse_response(payload)
        self.assertEqual(resp.message.role, "assistant")
        self.assertEqual(resp.message.content, "hello")
        self.assertIsNone(resp.message.tool_calls)
        self.assertEqual(resp.finish_reason, "stop")
        self.assertEqual(resp.usage.prompt_tokens, 7)
        self.assertEqual(resp.usage.completion_tokens, 3)
        # total filled when missing.
        self.assertEqual(resp.usage.total_tokens, 10)

    def test_parses_tool_call_response(self) -> None:
        payload = {
            "model": "x/y",
            "choices": [
                {
                    "finish_reason": "tool_calls",
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "tc_1",
                                "type": "function",
                                "function": {
                                    "name": "read",
                                    "arguments": '{"path":"x.txt"}',
                                },
                            }
                        ],
                    },
                }
            ],
        }
        resp = _parse_response(payload)
        self.assertEqual(resp.message.content, "")
        assert resp.message.tool_calls is not None
        self.assertEqual(len(resp.message.tool_calls), 1)
        tc = resp.message.tool_calls[0]
        self.assertEqual(tc.id, "tc_1")
        self.assertEqual(tc.function.name, "read")
        self.assertEqual(tc.function.arguments, '{"path":"x.txt"}')

    def test_parses_list_content(self) -> None:
        # Some providers return message.content as a list of parts.
        payload = {
            "model": "x",
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {
                        "role": "assistant",
                        "content": [
                            {"type": "text", "text": "hello "},
                            {"type": "text", "text": "world"},
                        ],
                    },
                }
            ],
        }
        resp = _parse_response(payload)
        self.assertEqual(resp.message.content, "hello world")

    def test_coerces_dict_arguments_to_json(self) -> None:
        # Some providers return a dict instead of a JSON string for arguments.
        payload = {
            "model": "x",
            "choices": [
                {
                    "finish_reason": "tool_calls",
                    "message": {
                        "role": "assistant",
                        "content": "",
                        "tool_calls": [
                            {
                                "id": "t1",
                                "type": "function",
                                "function": {
                                    "name": "read",
                                    "arguments": {"path": "x.txt"},
                                },
                            }
                        ],
                    },
                }
            ],
        }
        resp = _parse_response(payload)
        assert resp.message.tool_calls is not None
        self.assertEqual(
            json.loads(resp.message.tool_calls[0].function.arguments),
            {"path": "x.txt"},
        )

    def test_missing_choices_raises(self) -> None:
        with self.assertRaises(ChatClientError):
            _parse_response({"choices": []})


class ChatClientHttpTests(unittest.TestCase):
    def _make_client(self) -> ChatClient:
        return ChatClient(
            api_key="sk-test",
            model="google/gemini-3-flash-preview",
            base_url="https://openrouter.ai/api/v1",
            max_retries=2,
        )

    def test_chat_success_builds_correct_request(self) -> None:
        client = self._make_client()
        captured: dict = {}

        def fake_urlopen(req, timeout):  # type: ignore[no-untyped-def]
            captured["url"] = req.full_url
            captured["method"] = req.get_method()
            captured["headers"] = {
                k.lower(): v for k, v in req.header_items()
            }
            captured["body"] = json.loads(req.data)
            return _make_http_response(
                {
                    "model": "google/gemini-3-flash-preview",
                    "choices": [
                        {
                            "finish_reason": "stop",
                            "message": {"role": "assistant", "content": "ok"},
                        }
                    ],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1},
                }
            )

        with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            resp = client.chat([ChatMessage("user", "hi")])

        # URL and method
        self.assertEqual(
            captured["url"], "https://openrouter.ai/api/v1/chat/completions"
        )
        self.assertEqual(captured["method"], "POST")
        # Auth header with bearer token (header_items may lowercase keys)
        self.assertEqual(
            captured["headers"]["authorization"], "Bearer sk-test"
        )
        self.assertEqual(
            captured["headers"]["content-type"], "application/json"
        )
        # Body
        self.assertEqual(
            captured["body"]["model"], "google/gemini-3-flash-preview"
        )
        self.assertEqual(
            captured["body"]["messages"],
            [{"role": "user", "content": "hi"}],
        )
        # Response parsed
        self.assertEqual(resp.message.content, "ok")
        self.assertEqual(resp.finish_reason, "stop")

    def test_chat_with_tools_includes_tools_in_body(self) -> None:
        client = self._make_client()
        captured: dict = {}

        def fake_urlopen(req, timeout):  # type: ignore[no-untyped-def]
            captured["body"] = json.loads(req.data)
            return _make_http_response(
                {
                    "model": "x",
                    "choices": [
                        {
                            "finish_reason": "stop",
                            "message": {"role": "assistant", "content": ""},
                        }
                    ],
                }
            )

        dummy_tool = {
            "type": "function",
            "function": {
                "name": "read",
                "parameters": {"type": "object"},
            },
        }
        with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            client.chat(
                [ChatMessage("user", "x")],
                tools=[dummy_tool],
                tool_choice="auto",
                temperature=0.2,
                max_tokens=64,
            )

        self.assertEqual(captured["body"]["tools"], [dummy_tool])
        self.assertEqual(captured["body"]["tool_choice"], "auto")
        self.assertEqual(captured["body"]["temperature"], 0.2)
        self.assertEqual(captured["body"]["max_tokens"], 64)

    def test_retries_on_429(self) -> None:
        client = self._make_client()
        responses = [
            _make_http_error(429, {"error": {"message": "rate limit"}}),
            _make_http_error(429, {"error": {"message": "rate limit"}}),
            _make_http_response(
                {
                    "model": "x",
                    "choices": [
                        {
                            "finish_reason": "stop",
                            "message": {"role": "assistant", "content": "ok"},
                        }
                    ],
                }
            ),
        ]

        def fake_urlopen(req, timeout):  # type: ignore[no-untyped-def]
            item = responses.pop(0)
            if isinstance(item, urllib.error.HTTPError):
                raise item
            return item

        with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen), \
                mock.patch("time.sleep"):  # skip backoff delays in test
            resp = client.chat([ChatMessage("user", "x")])
        self.assertEqual(resp.message.content, "ok")
        # All three responses should have been consumed (2 failures + 1 success).
        self.assertEqual(responses, [])

    def test_retries_on_500_and_eventually_fails(self) -> None:
        client = self._make_client()
        call_count = {"n": 0}

        def fake_urlopen(req, timeout):  # type: ignore[no-untyped-def]
            call_count["n"] += 1
            # Build a fresh HTTPError each time — BytesIO is not rewindable
            # after the client calls exc.read() on the LAST failure's body.
            raise _make_http_error(500, {"error": {"message": "boom"}})

        with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen), \
                mock.patch("time.sleep"):
            with self.assertRaises(ChatClientError) as cm:
                client.chat([ChatMessage("user", "x")])
        self.assertEqual(cm.exception.status, 500)
        self.assertIn("boom", str(cm.exception))
        # max_retries=2 means: initial + 2 retries = 3 attempts.
        self.assertEqual(call_count["n"], 3)

    def test_no_retry_on_400(self) -> None:
        client = self._make_client()

        def fake_urlopen(req, timeout):  # type: ignore[no-untyped-def]
            raise _make_http_error(
                400, {"error": {"message": "bad request"}}
            )

        with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen) as p, \
                mock.patch("time.sleep"):
            with self.assertRaises(ChatClientError) as cm:
                client.chat([ChatMessage("user", "x")])
        self.assertEqual(cm.exception.status, 400)
        self.assertEqual(p.call_count, 1)  # no retries


class ClientFromEnvTests(unittest.TestCase):
    def test_uses_env_var(self) -> None:
        with mock.patch.dict(
            "os.environ", {"OPENROUTER_API_KEY": "sk-from-env"}, clear=False
        ):
            c = client_from_env(model="x/y")
            # access private field for the test — no other way to verify.
            self.assertEqual(c._api_key, "sk-from-env")  # noqa: SLF001
            self.assertEqual(c._model, "x/y")  # noqa: SLF001

    def test_raises_when_env_missing(self) -> None:
        with mock.patch.dict("os.environ", {}, clear=True):
            with self.assertRaises(RuntimeError):
                client_from_env(model="x/y")

    def test_custom_env_var(self) -> None:
        with mock.patch.dict(
            "os.environ", {"MY_KEY": "sk-custom"}, clear=False
        ):
            c = client_from_env(model="x/y", env_var="MY_KEY")
            self.assertEqual(c._api_key, "sk-custom")  # noqa: SLF001


if __name__ == "__main__":
    unittest.main()
