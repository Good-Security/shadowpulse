import json
from typing import AsyncIterator

import litellm
from litellm import acompletion

from config import settings


# Configure LiteLLM
litellm.drop_params = True  # Drop unsupported params per provider
litellm.modify_params = True  # Auto-fix message ordering for Anthropic


async def chat_completion(
    messages: list[dict],
    tools: list[dict] | None = None,
    stream: bool = False,
    model: str | None = None,
) -> dict:
    """Send a chat completion request to the configured LLM provider."""
    model = model or settings.LLM_MODEL

    kwargs = {
        "model": model,
        "messages": messages,
        "stream": stream,
        "temperature": 0.1,
        "max_tokens": 4096,
    }

    if tools:
        kwargs["tools"] = tools
        kwargs["tool_choice"] = "auto"

    response = await acompletion(**kwargs)

    if stream:
        return response  # Returns an async generator

    # Non-streaming: extract the response
    choice = response.choices[0]
    result = {
        "role": "assistant",
        "content": choice.message.content or "",
        "tool_calls": [],
    }

    if choice.message.tool_calls:
        for tc in choice.message.tool_calls:
            result["tool_calls"].append({
                "id": tc.id,
                "function": {
                    "name": tc.function.name,
                    "arguments": tc.function.arguments,
                },
            })

    return result


async def stream_completion(
    messages: list[dict],
    tools: list[dict] | None = None,
    model: str | None = None,
) -> AsyncIterator[dict]:
    """Stream a chat completion, yielding chunks."""
    model = model or settings.LLM_MODEL

    kwargs = {
        "model": model,
        "messages": messages,
        "stream": True,
        "temperature": 0.1,
        "max_tokens": 4096,
    }

    if tools:
        kwargs["tools"] = tools
        kwargs["tool_choice"] = "auto"

    response = await acompletion(**kwargs)

    content_buffer = ""
    tool_calls_buffer: dict[int, dict] = {}

    async for chunk in response:
        delta = chunk.choices[0].delta

        # Content streaming
        if delta.content:
            content_buffer += delta.content
            yield {"type": "content", "content": delta.content}

        # Tool call streaming
        if delta.tool_calls:
            for tc in delta.tool_calls:
                idx = tc.index
                if idx not in tool_calls_buffer:
                    tool_calls_buffer[idx] = {
                        "id": tc.id or "",
                        "function": {"name": "", "arguments": ""},
                    }
                if tc.id:
                    tool_calls_buffer[idx]["id"] = tc.id
                if tc.function:
                    if tc.function.name:
                        tool_calls_buffer[idx]["function"]["name"] = tc.function.name
                    if tc.function.arguments:
                        tool_calls_buffer[idx]["function"]["arguments"] += tc.function.arguments

        # Check if done
        if chunk.choices[0].finish_reason:
            if tool_calls_buffer:
                for idx in sorted(tool_calls_buffer.keys()):
                    yield {"type": "tool_call", **tool_calls_buffer[idx]}
            yield {"type": "done", "content": content_buffer}
            break
