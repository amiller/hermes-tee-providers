"""Fail closed on fields this content-only transport cannot encrypt."""


class UnsupportedEncryptedChat(ValueError):
    """A static refusal; never include caller or provider payloads."""


def require_text_request(payload):
    for field in ("tools", "functions"):
        if payload.get(field) not in (None, []):
            raise UnsupportedEncryptedChat("E2EE adapter supports text only; native tool definitions are not encrypted")
    for field in ("tool_choice", "function_call"):
        if payload.get(field) not in (None, "none", "auto"):
            raise UnsupportedEncryptedChat("E2EE adapter supports text only; native tool selection is unsupported")
    for message in payload.get("messages", []):
        if message.get("role") in ("tool", "function") or any(
            message.get(field) is not None for field in ("tool_calls", "function_call", "tool_call_id", "name")
        ):
            raise UnsupportedEncryptedChat("E2EE adapter supports text only; native tool history is not encrypted")
        if set(message) - {"role", "content", "reasoning", "reasoning_content"}:
            raise UnsupportedEncryptedChat("E2EE adapter supports text only; unsupported message fields are not encrypted")
        for field in ("content", "reasoning", "reasoning_content"):
            if message.get(field) is not None and not isinstance(message[field], str):
                raise UnsupportedEncryptedChat("E2EE adapter supports text only; non-text content is not encrypted")
    for field in ("tools", "functions", "tool_choice", "function_call", "parallel_tool_calls"):
        payload.pop(field, None)


def require_text_response(payload):
    for choice in payload.get("choices", []):
        if choice.get("finish_reason") in ("tool_calls", "function_call"):
            raise UnsupportedEncryptedChat("E2EE adapter refused an unsupported native tool response")
        for message in (choice.get("delta"), choice.get("message")):
            if message and any(message.get(field) is not None for field in ("tool_calls", "function_call", "nearai_tool_result")):
                raise UnsupportedEncryptedChat("E2EE adapter refused an unsupported native tool response")
