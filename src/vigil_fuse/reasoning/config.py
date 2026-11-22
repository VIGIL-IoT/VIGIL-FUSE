from __future__ import annotations

import math
import re
from dataclasses import dataclass, fields
from typing import Any
from urllib.parse import urlsplit


@dataclass(frozen=True)
class ReasoningConfig:
    provider: str = "ollama"
    model: str = "qwen3.5:4b"
    endpoint: str = "http://127.0.0.1:11434"
    context_tokens: int = 8192
    temperature: float = 0.1
    keep_alive: int = 0
    connection_timeout: float = 2.0
    generation_timeout: float = 120.0

    def __post_init__(self) -> None:
        if self.provider != "ollama":
            raise ValueError("reasoning.provider must be ollama")
        if not isinstance(self.model, str) or not re.fullmatch(r"[\w./:-]{1,128}", self.model):
            raise ValueError("reasoning.model must be a bounded local model name")
        # Cloud-backed Ollama names are not local inference.
        if "cloud" in self.model.casefold() or "/" in self.model or ".." in self.model:
            raise ValueError("reasoning.model must name a locally installed model")
        if not isinstance(self.endpoint, str) or any(char.isspace() for char in self.endpoint):
            raise ValueError("reasoning.endpoint must be a loopback HTTP URL")
        parsed = urlsplit(self.endpoint)
        if (
            parsed.scheme != "http"
            or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("reasoning.endpoint must be a loopback HTTP origin")
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError("reasoning.endpoint port is invalid")
        for name, minimum, maximum in (
            ("context_tokens", 4096, 131072),
            ("keep_alive", 0, 3600),
        ):
            value = getattr(self, name)
            if type(value) is not int or not minimum <= value <= maximum:
                raise ValueError(f"reasoning.{name} must be an integer in {minimum}..{maximum}")
        for name, lower, upper in (
            ("temperature", 0, 1),
            ("connection_timeout", 0.05, 30),
            ("generation_timeout", 0.05, 3600),
        ):
            value = getattr(self, name)
            if (
                type(value) not in {int, float}
                or not math.isfinite(value)
                or not lower <= value <= upper
            ):
                raise ValueError(f"reasoning.{name} must be a finite number in {lower}..{upper}")


def parse_config(data: dict[str, Any]) -> ReasoningConfig:
    unknown = set(data) - {item.name for item in fields(ReasoningConfig)}
    if unknown:
        raise ValueError(f"Unknown reasoning config keys: {', '.join(sorted(unknown))}")
    return ReasoningConfig(**data)
