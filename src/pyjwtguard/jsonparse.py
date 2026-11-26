"""Strict JSON parsing shared by headers and claims.

Python's ``json`` module silently keeps the last value for duplicate keys,
which is exactly how ``{"alg":"HS256","alg":"none"}`` and
``{"exp":9999999999,"exp":1}`` parser differentials are built. This module:

* rejects duplicate keys at every nesting level,
* rejects the ``NaN``, ``Infinity`` and ``-Infinity`` literals,
* rejects numeric overflow such as ``1e999`` that Python turns into infinity,
* requires the top level value to be a JSON object.
"""

from __future__ import annotations

import json
import math
from typing import Any, Dict, List, Tuple

from .errors import JSON_DUPLICATE_KEY, JSON_INVALID, JSON_NONFINITE, JwtGuardError


def _reject_duplicate_keys(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise JwtGuardError(JSON_DUPLICATE_KEY, "duplicate JSON key detected")
        result[key] = value
    return result


def _reject_constant(token: str) -> Any:
    raise JwtGuardError(JSON_NONFINITE, "non-finite JSON number is not allowed")


def _contains_surrogate(text: str) -> bool:
    return any(0xD800 <= ord(char) <= 0xDFFF for char in text)


def validate_json_tree(value: Any, *, invalid_code: str, nonfinite_code: str, context: str) -> None:
    """Validate JSON shaped data without recursive descent.

    The walk rejects non-finite numbers, lone surrogate code points, non-string
    object keys at every nesting level, and circular containers. It is iterative
    so hostile nesting cannot consume the Python call stack before the parser's
    own depth guard runs.
    """
    stack = [(value, False)]
    active = set()
    completed = set()
    while stack:
        item, closing = stack.pop()
        is_container = isinstance(item, (dict, list, tuple))
        if not is_container:
            if isinstance(item, float) and not math.isfinite(item):
                raise JwtGuardError(nonfinite_code, "{} contains a non-finite number".format(context))
            if isinstance(item, str) and _contains_surrogate(item):
                raise JwtGuardError(invalid_code, "{} contains a lone surrogate".format(context))
            continue
        marker = id(item)
        if closing:
            active.discard(marker)
            completed.add(marker)
            continue
        if marker in active:
            raise JwtGuardError(invalid_code, "{} contains a circular reference".format(context))
        if marker in completed:
            continue
        active.add(marker)
        stack.append((item, True))
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise JwtGuardError(invalid_code, "{} object keys must be strings".format(context))
                if _contains_surrogate(key):
                    raise JwtGuardError(invalid_code, "{} contains a lone surrogate key".format(context))
                stack.append((child, False))
        else:
            for child in item:
                stack.append((child, False))
    return None


def reject_nonfinite(value: Any, *, code: str, context: str) -> None:
    """Walk a JSON shaped value and reject every non-finite float."""
    validate_json_tree(value, invalid_code=code, nonfinite_code=code, context=context)


def parse_json_object(raw: bytes, *, code: str, context: str) -> Dict[str, Any]:
    """Parse one token segment into a JSON object using strict rules."""
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise JwtGuardError(JSON_INVALID, "{} is not valid UTF-8".format(context)) from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except JwtGuardError:
        raise
    except RecursionError as exc:
        raise JwtGuardError(JSON_INVALID, "{} is nested too deeply".format(context)) from exc
    except (ValueError, TypeError) as exc:
        raise JwtGuardError(JSON_INVALID, "{} is not valid JSON".format(context)) from exc
    if not isinstance(value, dict):
        raise JwtGuardError(code, "{} must be a JSON object".format(context))
    validate_json_tree(value, invalid_code=JSON_INVALID, nonfinite_code=JSON_NONFINITE, context=context)
    return value


__all__ = ["parse_json_object", "reject_nonfinite", "validate_json_tree"]
