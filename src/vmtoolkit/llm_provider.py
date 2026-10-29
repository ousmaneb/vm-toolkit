"""Everything specific to the AI provider: its package, client, request options and error types.

Swapping providers means replacing this file. The rest of the code goes through llm.py.
"""

from .llm import LLMError

NAME = "anthropic"
PACKAGE = "anthropic"
# Lets the provider retry a refused request on the model it recommends for that kind of request,
# instead of failing outright. Security questions trip refusal filters more often than most.
FALLBACK_BETA = "server-side-fallback-2026-07-01"


def client(api_key: str):
    import anthropic

    return anthropic.Anthropic(api_key=api_key)


def create(api, model: str, effort: str, **kwargs):
    import anthropic

    output_config = {"effort": effort, **kwargs.pop("output_config", {})}
    try:
        resp = api.beta.messages.create(model=model, betas=[FALLBACK_BETA], fallbacks="default",
                                        output_config=output_config, **kwargs)
    except anthropic.AuthenticationError:
        raise LLMError("The AI provider rejected the key. Check LLM_API_KEY in .env.") from None
    except anthropic.RateLimitError:
        raise LLMError("The AI provider's rate limit was reached; try again in a minute.") from None
    except anthropic.APIStatusError as e:
        raise LLMError(f"The AI provider returned error {e.status_code}: {e.message}") from None
    except anthropic.APIConnectionError:
        raise LLMError("Could not reach the AI provider. Check your connection.") from None
    if resp.stop_reason == "refusal":
        category = getattr(resp.stop_details, "category", None) if resp.stop_details else None
        raise LLMError(f"The LLM declined this request (category: {category or 'unspecified'}), and so did the "
                       "fallback model.")
    if resp.stop_reason == "max_tokens":
        raise LLMError("The answer was cut off at the length limit.")
    return resp


def text_of(resp) -> str:
    return "".join(b.text for b in resp.content if b.type == "text")


def documents(docs: list[tuple[str, str]]) -> list[dict]:
    """(title, text) source documents the answer is allowed to cite."""
    return [{"type": "document", "source": {"type": "text", "media_type": "text/plain", "data": text},
             "title": title, "citations": {"enabled": True}} for title, text in docs]


def cited_text(resp) -> list[tuple[str, list[int]]]:
    """The answer as (text, indexes of the documents that text cites) pieces."""
    pieces = []
    for block in resp.content:
        if block.type == "text":
            indexes = [c.document_index for c in getattr(block, "citations", None) or []
                       if getattr(c, "document_index", None) is not None]
            pieces.append((block.text, indexes))
    return pieces


def json_output(schema: dict) -> dict:
    return {"output_config": {"format": {"type": "json_schema", "schema": schema}}}


def usage(resp) -> tuple[str | None, int, int]:
    """(model that answered, input tokens, output tokens)."""
    return getattr(resp, "model", None), resp.usage.input_tokens, resp.usage.output_tokens
