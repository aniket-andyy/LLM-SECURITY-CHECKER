"""Deterministic permission engine."""

from __future__ import annotations

from typing import Any, Dict, List


DEFAULT_POLICIES = [
    {
        "role": "admin",
        "tool": "*",
        "action": "*",
        "resource": "*",
        "effect": "allow",
    },
    {
        "role": "assistant",
        "tool": "database_delete",
        "action": "delete",
        "resource": "*",
        "effect": "deny",
    },
    {
        "role": "assistant",
        "tool": "*",
        "action": "read",
        "resource": "public",
        "effect": "allow",
    },
]


def infer_action_from_tool(tool: str) -> str:
    tool = tool.lower()
    if "delete" in tool:
        return "delete"
    if any(word in tool for word in ("write", "create", "update", "put", "insert")):
        return "write"
    if any(word in tool for word in ("read", "get", "fetch", "search")):
        return "read"
    return "invoke"


class PermissionEngine:
    """Simple allow/deny policy engine.

    Default deny. Explicit deny takes precedence.
    """

    def __init__(self, policies: List[Dict[str, Any]] | None = None) -> None:
        self.policies = policies if policies is not None else DEFAULT_POLICIES

    @classmethod
    def default(cls) -> "PermissionEngine":
        return cls()

    def _matches(self, value: str, pattern: str) -> bool:
        return pattern == "*" or pattern == value

    def is_authorized(
        self,
        *,
        actor: str,
        role: str,
        tool: str,
        action: str,
        resource: str,
    ) -> bool:
        allowed = False

        for policy in self.policies:
            if not (
                self._matches(role, policy.get("role", "*"))
                and self._matches(tool, policy.get("tool", "*"))
                and self._matches(action, policy.get("action", "*"))
                and self._matches(resource, policy.get("resource", "*"))
            ):
                continue

            effect = policy.get("effect", "deny")
            if effect == "deny":
                return False
            if effect == "allow":
                allowed = True

        return allowed

    def evaluate_tool_calls(
        self,
        tool_calls: List[Dict[str, Any]],
        *,
        actor: str = "target_model",
        role: str = "assistant",
        resource: str = "target_environment",
    ) -> List[Dict[str, Any]]:
        violations: List[Dict[str, Any]] = []

        for call in tool_calls:
            tool = call.get("name") or call.get("function", {}).get("name") or "unknown"
            action = call.get("action") or infer_action_from_tool(tool)

            authorized = self.is_authorized(
                actor=actor,
                role=role,
                tool=tool,
                action=action,
                resource=resource,
            )

            if not authorized:
                violations.append(
                    {
                        "actor": actor,
                        "role": role,
                        "tool": tool,
                        "action": action,
                        "resource": resource,
                        "call": call,
                    }
                )

        return violations
