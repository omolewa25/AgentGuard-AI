from __future__ import annotations

import ast
import operator
from typing import Any

# Only these comparison operators are permitted in policy conditions.
_ALLOWED_COMPARATORS = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    ast.In: lambda a, b: a in b,
    ast.NotIn: lambda a, b: a not in b,
}


class PolicyConditionError(ValueError):
    """Raised when a condition expression is invalid or uses disallowed syntax."""


# JSON/YAML authors naturally write lowercase booleans/null; treat them as
# literals so `external == true` doesn't silently parse as a bare name.
_LITERAL_NAMES = {
    "true": True,
    "false": False,
    "null": None,
    "none": None,
}


def evaluate_condition(expr: str, context: dict[str, Any]) -> bool:
    """Safely evaluate a boolean policy expression against a context dict.

    Supports names (resolved from context), literals, boolean operators
    (and/or/not), membership (in/not in), and comparisons. It is intentionally
    NOT a general Python evaluator: function calls, attribute access, arithmetic,
    and dunder access are rejected, so untrusted policy files cannot execute code.
    """
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError as exc:
        raise PolicyConditionError(f"Invalid condition syntax: {expr!r}") from exc
    return bool(_eval(tree.body, context))


def _eval(node: ast.AST, ctx: dict[str, Any]) -> Any:
    if isinstance(node, ast.BoolOp):
        values = [_eval(value, ctx) for value in node.values]
        if isinstance(node.op, ast.And):
            return all(values)
        if isinstance(node.op, ast.Or):
            return any(values)
        raise PolicyConditionError("Unsupported boolean operator.")

    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return not _eval(node.operand, ctx)

    if isinstance(node, ast.Compare):
        left = _eval(node.left, ctx)
        for op, comparator in zip(node.ops, node.comparators):
            func = _ALLOWED_COMPARATORS.get(type(op))
            if func is None:
                raise PolicyConditionError(f"Unsupported comparison: {type(op).__name__}")
            right = _eval(comparator, ctx)
            if not func(left, right):
                return False
            left = right
        return True

    if isinstance(node, ast.Name):
        if node.id in _LITERAL_NAMES:
            return _LITERAL_NAMES[node.id]
        return ctx.get(node.id)

    if isinstance(node, ast.Constant):
        return node.value

    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return [_eval(element, ctx) for element in node.elts]

    raise PolicyConditionError(f"Unsupported expression element: {type(node).__name__}")
