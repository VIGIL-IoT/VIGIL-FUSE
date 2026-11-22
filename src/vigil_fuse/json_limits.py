"""Bounded JSON serialization for static evidence artifacts."""

from __future__ import annotations

from dataclasses import fields, is_dataclass
import json


def bounded_json(value: object, limit: int, *, indent: int | None = None) -> str:
    class Encoder(json.JSONEncoder):
        def default(self, item: object) -> object:
            if is_dataclass(item) and not isinstance(item, type):
                return {field.name: getattr(item, field.name) for field in fields(item)}
            return super().default(item)

    encoder = Encoder(ensure_ascii=True, sort_keys=True, indent=indent)
    chunks: list[str] = []
    size = 1
    for chunk in encoder.iterencode(value):
        size += len(chunk)
        if size > limit:
            raise ValueError("JSON output size limit exceeded")
        chunks.append(chunk)
    return "".join(chunks) + "\n"
