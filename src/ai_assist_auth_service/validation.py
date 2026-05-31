from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping


class FrozenDict(dict):
    def __readonly(self, *args: object, **kwargs: object) -> None:
        raise TypeError("FrozenDict is immutable.")

    __setitem__ = __readonly
    __delitem__ = __readonly
    clear = __readonly
    pop = __readonly
    popitem = __readonly
    setdefault = __readonly
    update = __readonly


def require_non_empty_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value.strip()) == 0:
        raise TypeError(f"{field} must be a non-empty string.")
    return value


def require_datetime(value: Any, field: str) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        source = value[:-1] + "+00:00" if value.endswith("Z") else value
        parsed = datetime.fromisoformat(source)
    else:
        raise TypeError(f"{field} must be a valid datetime.")

    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def clone_datetime(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromtimestamp(value.timestamp(), tz=timezone.utc)


def to_iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    normalized = require_datetime(value, "value")
    return normalized.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def freeze(value: Any) -> Any:
    if isinstance(value, FrozenDict):
        return value
    if isinstance(value, Mapping):
        return FrozenDict({key: freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(freeze(item) for item in value)
    if isinstance(value, tuple):
        return tuple(freeze(item) for item in value)
    return value
