# Excerpt from blackwing/security/approvals.py
# The per tool call gate: live constraints, deterministic rules, intent grants, the isolated
# LLM safety judge (strict JSON verdict, fails closed), then a human approval wait.
# Copied without changes from the private Blackwing source. Imports and the rest of the
# module are omitted, so this file does not run on its own.
# Copyright (c) 2026 softdyne. All rights reserved. Shown for review only; see LICENSE.

def is_high_risk_call(tool_name: str, args: dict[str, Any], *, is_read_only: bool = False) -> bool:
    """Return True when a tool invocation warrants safety-judge or strict-HITL evaluation."""
    if is_read_only:
        return False
    if tool_name in HIGH_RISK_TOOLS:
        return True
    if tool_name == "WebFetch":
        method = str(args.get("method") or "GET").strip().upper()
        return method not in ("GET", "HEAD", "OPTIONS")
    return False


def _strip_code_fence(text: str) -> str:
    """Remove a surrounding Markdown code fence (```json ... ```), if the text has a complete one."""
    if text.startswith("```"):
        lines = text.splitlines()
        if len(lines) >= 3 and lines[-1].strip().startswith("```"):
            return "\n".join(lines[1:-1]).strip()
    return text


def _reject_json_constant(val: str) -> Any:
    """``json.loads`` hook: refuse ``NaN``/``Infinity``, which are not valid JSON."""
    raise ValueError(f"invalid JSON constant: {val}")


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """``json.loads`` hook: refuse objects that repeat a key (an attacker could hide a second ``action``)."""
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"duplicate safety judge field: {key!r}")
        obj[key] = value
    return obj


def _parse_judge_json(raw_text: str) -> tuple[str, str]:
    """Parse strict JSON verdict from ``safety_judge``; raise ValueError on any ambiguity."""
    text = str(raw_text or "").strip()
    if not text:
        raise ValueError("empty safety judge response")
    text = _strip_code_fence(text)
    parsed = json.loads(text, parse_constant=_reject_json_constant, object_pairs_hook=_object_without_duplicates)
    if not isinstance(parsed, dict):
        raise ValueError("safety judge response must be a JSON object")
    raw_action = parsed.get("action")
    if not isinstance(raw_action, str):
        raise ValueError(f"invalid safety judge action type: {type(raw_action).__name__}")
    action = raw_action.strip().lower()
    if action not in APPROVAL_ACTIONS:
        raise ValueError(f"invalid safety judge action: {action!r}")
    raw_reason = parsed.get("reason")
    if not isinstance(raw_reason, str) or not raw_reason.strip():
        raise ValueError("safety judge must provide a non-empty reason string")
    return action, raw_reason.strip()[:500]


class SafetyJudge:
    """Isolated LLM safety judge (profile/role ``safety_judge``, enabled by default per task).

    Uses an explicit ``safety_judge`` binding/profile when configured, otherwise falls back to
    the active configured LLM profile. Receives ONLY tool name, canonical arguments, and trusted
    operator task goal/constraints — never untrusted target responses, captured traffic, or
    worker-generated reasoning. Any failure, timeout, or malformed verdict fails closed to ``ask``.
    """

    def __init__(self, store: Any, llm_pool: LLMPool, *, deadline_sec: float = 15.0) -> None:
        self.store = store
        self.llm_pool = llm_pool
        self.deadline_sec = max(2.0, float(deadline_sec))

    def _resolve_chain(self) -> list[dict[str, Any]]:
        resolver = getattr(self.store, "resolve_safety_judge_chain", None)
        if callable(resolver):
            return list(resolver())
        fallback = getattr(self.store, "resolve_optional_llm_chain", None)
        if callable(fallback):
            return list(fallback("safety_judge"))
        return []

    def evaluate(
        self,
        *,
        task_id: int,
        tool_name: str,
        canonical_args: str,
        trusted_goal: str,
        trusted_constraints: list[dict[str, Any]],
        cancel_event: threading.Event | None = None,
        chain: list[dict[str, Any]] | None = None,
    ) -> tuple[str, str]:
        # Strictly trusted operator-authored context + exact tool invocation only.
        constraint_lines = [
            f"- [{str(c.get('rule_type') or 'deny').upper()}] {str(c.get('rule_text') or '')}"
            + (f" ({c['reason']})" if c.get("reason") else "")
            for c in trusted_constraints
            if str(c.get("rule_text") or "").strip()
        ]
        goal = str(trusted_goal or "")
        if len(canonical_args) > 12_000 or len(goal) > 4_000 or len(constraint_lines) > 50:
            return "ask", "Complete invocation and operator policy exceed the judge review budget"
        user_payload = {
            "tool_name": str(tool_name),
            "canonical_arguments": canonical_args,
            "trusted_operator_task_goal": goal,
            "trusted_operator_constraints": constraint_lines,
        }
        prompt = (
            "Evaluate this single pending tool invocation against the trusted operator instructions.\n"
            + json.dumps(user_payload, ensure_ascii=False, indent=2)
        )
        try:
            resolved_chain = self._resolve_chain() if chain is None else list(chain)
            if not resolved_chain:
                return "ask", "Safety judge is not configured; failing closed to operator approval"
            turn = self.llm_pool.chat_turn(
                resolved_chain,
                SAFETY_JUDGE_SYSTEM_PROMPT,
                Conversation(prompt),
                tools=[],
                session_id=f"safety-judge-task-{task_id}",
                cancel_event=cancel_event,
                deadline_sec=self.deadline_sec,
            )
            return _parse_judge_json(turn.text)
        except LLMCancelledError:
            raise
        except Exception as exc:  # fail closed on any provider/parse error
            _logger.warning("safety_judge failed closed to 'ask' on %s (task=%s): %s", tool_name, task_id, exc)
            return "ask", f"Safety judge failed closed ({type(exc).__name__}); operator approval required"



class ApprovalEngine:
    # ... constructor and helpers omitted ...

    def check_and_wait(
        self,
        *,
        task_id: int,
        intent_id: int,
        role: str,
        tool_name: str,
        args: dict[str, Any],
        is_read_only: bool = False,
        cancel_event: threading.Event | None = None,
        shutdown_event: threading.Event | None = None,
        timeout_sec: int | None = None,
    ) -> ApprovalOutcome:
        """Evaluate live constraints, rules, optional safety judge, and block on HITL approval if needed."""
        tid = int(task_id or 0)
        iid = int(intent_id or 0)
        canon = canonical_args_json(args)
        digest = args_sha256(canon)

        # 1. Live security-critical operator task constraints are ALWAYS enforced first.
        constraints = self.store.list_constraints(tid) if tid > 0 else []
        violated = evaluate_constraints_for_tool(constraints, tool_name, args, canon)
        if violated is not None:
            return _constraint_denial(*violated)

        # Operator chat runs directly for the operator on a restricted read/steering toolset.
        if role == "operator_chat" or tid <= 0:
            return ApprovalOutcome(allowed=True, state="allowed")

        task = self.store.get_task(tid) or {}
        approval_mode = str(task.get("approval_mode") or "rules").strip().lower()
        if approval_mode == "off":
            return ApprovalOutcome(allowed=True, state="allowed")
        safety_judge_enabled = bool(task.get("safety_judge_enabled", True))

        # 2. Deterministic rule evaluation (priority -> task scope -> deny > ask > allow -> id).
        rules = self.store.list_approval_rules(task_id=tid, include_global=True, enabled_only=True)
        matched = select_matching_rule(
            rules,
            task_id=tid,
            tool_name=tool_name,
            args=args,
            canonical_json=canon,
        )

        matched_rule_id = int(matched["id"]) if matched is not None else None
        matched_summary = _rule_summary(matched) if matched is not None else ""
        action = str(matched["action"]).lower() if matched is not None else ""
        judge_action = ""
        judge_reason = ""
        if matched is not None:
            decided = self._apply_matched_rule(
                matched, matched_summary, tid=tid, iid=iid, role=role, tool_name=tool_name, canon=canon, digest=digest
            )
            if decided is not None:
                return decided

        # 3. Check reusable per-intent approval before asking judge or operator.
        # (Note: explicit 'deny' constraints and 'deny' rules above ALWAYS override approved_intent.)
        if iid > 0 and self.store.has_intent_approval(tid, iid, tool_name):
            return ApprovalOutcome(
                allowed=True,
                state="approved_intent",
                reason=f"Covered by active intent approval for '{tool_name}'",
                matched_rule_id=matched_rule_id,
            )

        # 4. High-risk calls without deterministic rule coverage: Safety Judge (on by default) / strict mode.
        if action == "":
            immediate, hr_summary, judge_action, judge_reason = self._evaluate_high_risk_policy(
                tid=tid,
                iid=iid,
                role=role,
                tool_name=tool_name,
                args=args,
                canon=canon,
                digest=digest,
                is_read_only=is_read_only,
                approval_mode=approval_mode,
                safety_judge_enabled=safety_judge_enabled,
                task=task,
                constraints=constraints,
                cancel_event=cancel_event,
            )
            if immediate is not None:
                return immediate
            if hr_summary:
                matched_summary = hr_summary

        # 5. Persist pending request and wait until operator decides, timeout expires, or run cancels.
        eff_timeout = (
            max(MIN_APPROVAL_TIMEOUT_SEC, min(MAX_APPROVAL_TIMEOUT_SEC, int(timeout_sec)))
            if timeout_sec is not None
            else self.default_timeout_sec
        )
        return self._create_and_wait(
            task_id=tid,
            intent_id=iid,
            role=role,
            tool_name=tool_name,
            canonical_args=canon,
            args_hash=digest,
            matched_rule_id=matched_rule_id,
            matched_rule_summary=matched_summary,
            judge_action=judge_action,
            judge_reason=judge_reason,
            timeout_sec=eff_timeout,
            cancel_event=cancel_event,
            shutdown_event=shutdown_event,
        )
