from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


def execution_decision(engagement, *, active: bool, lab_only: bool = False, approved: bool = False) -> Decision:
    if engagement["kill_switch"]:
        return Decision(False, "engagement kill switch is active")
    if lab_only and not engagement["lab_mode"]:
        return Decision(False, "this operation is restricted to isolated lab engagements")
    if active and not engagement["active_enabled"]:
        return Decision(False, "active execution is disabled for this engagement")
    if active and not approved:
        return Decision(False, "active execution requires explicit approval")
    return Decision(True, "policy requirements satisfied")

