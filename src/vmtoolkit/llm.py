"""LLM plumbing shared by the advisory extractor, triage and plain-English questions.

Which provider and model to use is a setting ([llm] in config.toml, LLM_API_KEY in .env); the
provider-specific code lives in llm_provider.py.
"""

import json

from .config import ConfigError, Settings, get_secret


class LLMError(Exception):
    pass


def options(settings: Settings) -> dict:
    cfg = settings.section("llm")
    return {"provider": cfg.get("provider", ""), "model": cfg.get("model", ""),
            "effort": cfg.get("effort", "medium"), "send_hostnames": bool(cfg.get("send_hostnames", False)),
            "prices": cfg.get("prices", {})}


def _provider(settings: Settings):
    from . import llm_provider

    opts = options(settings)
    if not opts["provider"] or not opts["model"]:
        raise ConfigError("Set provider and model under [llm] in config.toml to use the LLM features.")
    if opts["provider"] != llm_provider.NAME:
        raise ConfigError(f"[llm] provider {opts['provider']!r} isn't supported; llm_provider.py implements "
                          f"{llm_provider.NAME!r}.")
    return llm_provider


def client(settings: Settings):
    provider = _provider(settings)
    try:
        __import__(provider.PACKAGE)
    except ImportError:
        raise ConfigError('The LLM features need extra packages: pip install -e ".[llm]"') from None
    if settings.offline:
        raise ConfigError("The LLM features call the AI provider, so they don't work with --offline.")
    return provider.client(get_secret("LLM_API_KEY", required=True))


def create(api, settings: Settings, **kwargs):
    opts = options(settings)
    return _provider(settings).create(api, opts["model"], opts["effort"], **kwargs)


def text_of(resp, settings: Settings) -> str:
    return _provider(settings).text_of(resp)


def answered_by(resp, settings: Settings) -> str:
    """The model that actually answered: a refused request may be retried on a fallback model."""
    return _provider(settings).usage(resp)[0] or options(settings)["model"]


def documents(settings: Settings, docs: list[tuple[str, str]]) -> list[dict]:
    return _provider(settings).documents(docs)


def cited_text(resp, settings: Settings) -> list[tuple[str, list[int]]]:
    return _provider(settings).cited_text(resp)


def create_json(api, settings: Settings, schema: dict, **kwargs) -> tuple[dict, object]:
    provider = _provider(settings)
    resp = create(api, settings, **provider.json_output(schema), **kwargs)
    return json.loads(provider.text_of(resp)), resp


def usage_line(resp, settings: Settings) -> str:
    opts = options(settings)
    _, tokens_in, tokens_out = _provider(settings).usage(resp)
    model = answered_by(resp, settings)
    line = f"LLM ({model}): {tokens_in:,} input + {tokens_out:,} output tokens"
    # [llm.prices] maps a model to [input, output] dollars per million tokens; optional.
    price = opts["prices"].get(model)
    if price:
        line += f", about ${(tokens_in * price[0] + tokens_out * price[1]) / 1e6:.3f}"
    if model != opts["model"]:
        line += f". Answered by {model} after {opts['model']} declined."
    return line + "."
