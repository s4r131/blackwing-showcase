# Excerpt from blackwing/runtime/llm/pool.py
# One model turn across a failover chain of LLM profiles, with health cooldowns, a shared
# deadline, and jittered exponential backoff.
# Copied without changes from the private Blackwing source. Imports and the rest of the
# module are omitted, so this file does not run on its own.
# Copyright (c) 2026 softdyne. All rights reserved. Shown for review only; see LICENSE.

class LLMPool:
    # ... constructor, health tracking and request fitting omitted ...

    def _candidates(self, chain: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Ready profiles in chain order followed by cooling profiles sorted by earliest recovery (LLM-06)."""
        now = self._clock()
        with self._lock:
            until = {self._key(p): (self._health.get(self._key(p)) or _Health()).cooldown_until for p in chain}
        ready = [p for p in chain if until[self._key(p)] <= now]
        cooling = sorted((p for p in chain if until[self._key(p)] > now), key=lambda p: until[self._key(p)])
        return ready + cooling

    # ... other methods omitted ...

    def _run(
        self,
        chain: list[dict[str, Any]],
        system_prompt: str,
        conversation: Conversation,
        tools: list[Any],
        session_id: str,
        cancel_event: threading.Event | None,
        deadline_sec: float | None,
        max_tokens: int | None,
        *,
        spill_dir: Path | None = None,
        critical_context: dict[str, Any] | None = None,
        extra_secrets: Iterable[str] = (),
        stream: ReplyStream | None = None,
    ) -> TurnResult:
        if not chain:
            raise LLMChainExhaustedError("No LLM profile is available", [], [])
        cancel = cancel_event or self._never
        stream_guard = _StreamGuard(stream) if stream is not None else None
        usage = TurnUsage()
        errors: list[str] = []
        causes: list[LLMError] = []
        attempts = 0
        tool_names = {t.name for t in tools}
        candidates = self._candidates(chain)
        deadline: float | None = None
        for idx, profile in enumerate(candidates):
            key = self._key(profile)
            label = str(profile.get("name", "LLM"))
            try:
                resolved = self._with_secret(profile)
            except LLMAuthOrConfigError as exc:
                self._record_turn_failure(key, exc)
                errors.append(f"{label}: {exc}")
                causes.append(exc)
                continue
            client = LLMClient(resolved)
            eff_turn_budget = float(deadline_sec) if deadline_sec else (
                float(client.turn_deadline_sec) if client.turn_deadline_sec > 0 else self.deadline_sec
            )
            result, deadline, attempts, last_err = self._run_candidate(
                client=client,
                key=key,
                profile=profile,
                candidates_left=len(candidates) - idx,
                system_prompt=system_prompt,
                conversation=conversation,
                tools=tools,
                tool_names=tool_names,
                session_id=session_id,
                cancel=cancel,
                deadline=deadline,
                eff_turn_budget=eff_turn_budget,
                max_tokens=max_tokens,
                usage=usage,
                attempts=attempts,
                errors=errors,
                causes=causes,
                spill_dir=spill_dir,
                critical_context=critical_context,
                extra_secrets=extra_secrets,
                stream_guard=stream_guard,
            )
            if result is not None:
                return result
            if last_err is not None:
                self._record_turn_failure(key, last_err)
        raise LLMChainExhaustedError("All LLM profiles failed: " + " | ".join(errors[-6:]), errors, causes)


    # ... other methods omitted ...

    def _check(self, cancel: threading.Event, deadline: float) -> None:
        if cancel.is_set():
            raise LLMCancelledError("LLM turn cancelled")
        if self._monotonic() >= deadline:
            raise LLMDeadlineError("LLM turn deadline exhausted")

    def _timeout(
        self,
        deadline: float,
        candidates_left: int = 1,
        *,
        max_req_sec: float = MAX_REQUEST_TIMEOUT_SEC,
    ) -> float:
        remaining = deadline - self._monotonic()
        if remaining <= 1.0:
            raise LLMDeadlineError("LLM turn deadline exhausted")
        share = remaining / max(1, int(candidates_left))
        return max(1.0, min(float(max_req_sec), share))

    def _backoff(self, tries: int, retry_after: float | None, deadline: float) -> float | None:
        """Seconds to wait before retry ``tries + 1``; None when ``Retry-After`` outlasts the deadline."""
        remaining = deadline - self._monotonic() - 1.0
        if retry_after is not None:
            return retry_after if retry_after <= remaining else None
        delay = min(BACKOFF_CAP_SEC, BACKOFF_BASE_SEC * (2 ** (tries - 1)))
        delay = delay * (0.5 + self._rng.random() / 2)
        return max(0.0, min(delay, remaining))

