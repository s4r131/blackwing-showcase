# Excerpts from blackwing/runtime/llm/client.py and blackwing/runtime/llm/sdk_adapter.py
# How one agent turn reaches a cloud model (Anthropic, OpenAI, or OpenAI Responses) through
# Pydantic AI: the endpoint check, building the SDK model with an isolated credential, preparing
# the request and its settings, then sending it as a cancellable task with a deadline.
# Copied without changes from the private Blackwing source. Imports and the rest of each module
# are omitted, so this file does not run on its own.
# Copyright (c) 2026 softdyne. All rights reserved. Shown for review only; see LICENSE.

# ── blackwing/runtime/llm/client.py ────────────────────────────────────────────

class LLMClient:
    # ... profile parsing and token counting omitted ...

    def check_endpoint_security(self) -> None:
        """SEC-07: never send an API key over plain HTTP to a non-loopback host."""
        parsed = urlparse(self.base_url)
        if self.api_key and parsed.scheme.lower() == "http" and not _is_loopback_host(parsed.hostname or ""):
            raise LLMAuthOrConfigError("refusing to send an API key over plain HTTP")

    # ... prepare() omitted ...

    def send(
        self,
        prepared: PreparedRequest,
        *,
        timeout: float,
        session_id: str = "",
        cancel_event: threading.Event | None = None,
        use_streaming: bool | None = None,
        turn_deadline: float | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        on_text: Callable[[str], None] | None = None,
    ) -> ProviderReply:
        """Send ``prepared`` with native async cancellation (C-2, R-2, R-3); provider failures raise ``LLMError``."""
        from . import sdk_adapter

        self.check_endpoint_security()
        return sdk_adapter.send(
            self,
            prepared.sdk,
            timeout=float(timeout),
            streaming=self.streaming if use_streaming is None else bool(use_streaming),
            session_id=session_id,
            cancel_event=cancel_event,
            turn_deadline=turn_deadline,
            monotonic=monotonic,
            on_text=on_text,
        )


# ── blackwing/runtime/llm/sdk_adapter.py ──────────────────────────────────────

"""Pydantic AI wire layer (PYDANTIC_AI_ADAPTERS.md): the only path Blackwing uses to talk to a model.

This module is the only place that imports ``pydantic_ai``. It owns
one model request: rendering a provider-neutral ``ConversationView`` into SDK messages, sending it through the
SDK's native model classes, and decoding the native ``ModelResponse``. Failover, retries, deadlines, context
fitting and persistence stay in ``LLMPool``/``ContextManager``; provider failures leave as ``LLMError`` so the
pool's branches are unchanged, and anything that is not a provider failure is re-raised untouched.

Design rules (PYDANTIC_AI_PHASE0.md, rollout-step-5 sign-off):
- Native async cancellation: the request runs as an asyncio task; cancel or deadline cancels the task and
  waits for it to unwind (the SDK and ``httpx2`` close the connection) before returning. No watchdog thread,
  no orphaned request, and a retry never overlaps the attempt it replaces.
- SDK retries are off (client and settings), so one Blackwing attempt is one request.
- Native token counting (``Model.count_tokens``) for Anthropic and OpenAI Responses, used by context fitting.
- Native exception categories are mapped narrowly; only the known Anthropic-compatible "stream without usage"
  crash is treated as a provider compatibility failure.
- ``_WireTransport`` does only what the SDK cannot be configured to do: credential isolation (the SDK clients
  read ``ANTHROPIC_AUTH_TOKEN``/``OPENAI_ORG_ID``/... from the environment; Blackwing sends only the profile's
  own key), dropping ``stream_options`` for endpoints that reject it, surfacing a 2xx error body as an HTTP
  error, replaying a JSON reply to a streaming request into a non-streaming SDK call (no second request),
  filling legacy positional ids for id-less tool calls, and stripping ``X-Stainless-*`` host fingerprints.
"""


# 1. One HTTP client and SDK model per request; only the profile's own key is ever sent.

def _http_client(client: LLMClient) -> httpx2.AsyncClient:
    inner = httpx2.AsyncHTTPTransport(verify=bool(client.tls_verify), proxy=_proxy_for(client), trust_env=True)
    return httpx2.AsyncClient(
        transport=_WireTransport(inner, api_key=client.api_key),
        follow_redirects=False,
        timeout=httpx2.Timeout(600.0, connect=CONNECT_TIMEOUT_SEC),
    )


def build_model(client: LLMClient, http_client: httpx2.AsyncClient) -> Any:
    """Build the Pydantic AI model for ``client``'s profile; the key placeholder never leaves the transport."""
    if client.format == "anthropic":
        anth = AsyncAnthropic(base_url=_strip_v1(client.base_url), api_key=_KEY_PLACEHOLDER, max_retries=0, http_client=http_client)
        return AnthropicModel(client.model, provider=AnthropicProvider(anthropic_client=anth))
    oai = AsyncOpenAI(base_url=client.base_url, api_key=_KEY_PLACEHOLDER, max_retries=0, http_client=http_client)
    provider = OpenAIProvider(openai_client=oai)
    if client.format == "openai-responses":
        return OpenAIResponsesModel(client.model, provider=provider, profile=_openai_profile(client))
    return OpenAIChatModel(client.model, provider=provider, profile=_openai_profile(client))


# 2. Render the conversation and tools into a Pydantic AI request, with per provider settings.

def prepare(
    client: LLMClient,
    system_prompt: str,
    view: ConversationView,
    tools: list[Any],
    max_tokens: int | None,
    *,
    include_usage: bool,
) -> SdkRequest:
    schemas = [{"name": tool.name, "description": tool.description, "input_schema": tool.input_schema} for tool in tools]
    header_json = json.dumps({"system": system_prompt, "tools": schemas}, ensure_ascii=False, default=str)
    est = estimate_prompt_tokens(header_json + view.estimate_text())
    return SdkRequest(
        messages=to_model_messages(system_prompt, view),
        params=ModelRequestParameters(function_tools=_tool_definitions(tools), allow_text_output=True),
        max_tokens=int(max_tokens) if max_tokens else max(0, client.max_tokens),
        include_usage=bool(include_usage),
        est_prompt_tokens=est,
    )


def _settings(client: LLMClient, req: SdkRequest, *, timeout: float, streaming: bool, session_id: str) -> ModelSettings:
    timeout_sec = float(timeout)  # same socket timeouts as LLMClient._httpx_timeout
    read = max(STREAM_IDLE_TIMEOUT_SEC, min(timeout_sec, STREAM_IDLE_TIMEOUT_SEC)) if streaming else timeout_sec
    headers: dict[str, str] = {}
    if client.session_header_key and session_id:
        headers[client.session_header_key] = session_id
    if streaming and not req.include_usage:
        headers[_DROP_STREAM_OPTIONS] = "1"
    settings: dict[str, Any] = {
        "timeout": httpx2.Timeout(
            timeout_sec, connect=min(CONNECT_TIMEOUT_SEC, timeout_sec), read=read, pool=min(10.0, timeout_sec)
        ),
        "first_event_timeout": timeout_sec,
        "max_retries": 0,
        "extra_headers": headers,
    }
    if client.format == "anthropic":
        settings["max_tokens"] = req.max_tokens or 4096
        settings["anthropic_cache_instructions"] = True
        if req.params.function_tools:
            settings["anthropic_cache_tool_definitions"] = True
    elif req.max_tokens > 0:
        settings["max_tokens"] = req.max_tokens
    if client.format == "openai-responses":
        settings["openai_store"] = False
    return cast(ModelSettings, settings)


# 3. Send it: streamed or not, as an asyncio task that is cancelled cleanly on cancel or deadline.

async def _guarded[T](
    work: Coroutine[Any, Any, T],
    *,
    timeout: float,
    streaming: bool,
    cancel_event: threading.Event | None,
    turn_deadline: float | None,
    first_event: threading.Event,
    monotonic: Callable[[], float],
) -> T:
    """Await ``work`` as a task; on cancel or deadline, cancel it and wait until it has fully unwound.

    Deadline rules match the legacy watchdog: before the first stream event the request share applies; once a
    stream is flowing under a turn deadline, the later of the two (plus 1 s grace) applies.
    """
    req_deadline = monotonic() + float(timeout)
    task = asyncio.ensure_future(work)
    try:
        while True:
            done, _ = await asyncio.wait({task}, timeout=_POLL_SEC)
            if done:
                return task.result()
            if cancel_event is not None and cancel_event.is_set():
                raise LLMCancelledError("LLM turn cancelled")
            limit = req_deadline
            if streaming and turn_deadline and first_event.is_set():
                limit = max(req_deadline, float(turn_deadline)) + 1.0
            if monotonic() >= limit:
                raise LLMRetryableError("request timed out", timeout=True)
    finally:
        if not task.done():
            task.cancel()
            with contextlib.suppress(BaseException):
                await task  # the SDK/httpx2 close the connection while unwinding


async def _request_async(
    client: LLMClient,
    req: SdkRequest,
    *,
    timeout: float,
    streaming: bool,
    session_id: str,
    first_event: threading.Event,
    on_text: Callable[[str], None] | None = None,
) -> ProviderReply:
    settings = _settings(client, req, timeout=timeout, streaming=streaming, session_id=session_id)
    async with _http_client(client) as http_client:
        model = build_model(client, http_client)
        if not streaming:
            resp = await model_request(model, req.messages, model_settings=settings, model_request_parameters=req.params)
            reply = _raise_if_refused(reply_from_response(client.format, resp, streamed=False), resp)
            return _send_whole_text(reply, on_text)
        try:
            async with model_request_stream(model, req.messages, model_settings=settings, model_request_parameters=req.params) as stream:
                async for event in stream:
                    first_event.set()
                    if on_text is not None:
                        piece = _text_piece(event)
                        if piece:
                            on_text(piece)
                final = stream.get()
                return _raise_if_refused(reply_from_response(client.format, final, streamed=True), final)
        except ModelHTTPError as exc:
            if (exc.headers or {}).get(JSON_INSTEAD_OF_SSE) != "1":
                raise
        # G8: the endpoint answered with plain JSON. The transport kept that reply; this non-streaming call is
        # served from it (no second request), and the pool remembers the profile as non-streaming.
        plain = _settings(client, req, timeout=timeout, streaming=False, session_id=session_id)
        resp = await model_request(model, req.messages, model_settings=plain, model_request_parameters=req.params)
        reply = dataclasses.replace(reply_from_response(client.format, resp, streamed=False), streaming_unsupported=True)
        return _send_whole_text(_raise_if_refused(reply, resp), on_text)


def send(
    client: LLMClient,
    req: SdkRequest,
    *,
    timeout: float,
    streaming: bool,
    session_id: str = "",
    cancel_event: threading.Event | None = None,
    turn_deadline: float | None = None,
    monotonic: Callable[[], float] = time.monotonic,
    on_text: Callable[[str], None] | None = None,
) -> ProviderReply:
    """Send one request; provider failures raise ``LLMError``, anything else propagates unchanged.

    ``on_text``, when given, receives the reply text as it arrives (or all at once without streaming).
    """
    first_event = threading.Event()
    work = _request_async(
        client, req, timeout=timeout, streaming=streaming, session_id=session_id, first_event=first_event, on_text=on_text
    )
    try:
        return _run(
            _guarded(
                work,
                timeout=timeout,
                streaming=streaming,
                cancel_event=cancel_event,
                turn_deadline=turn_deadline,
                first_event=first_event,
                monotonic=monotonic,
            )
        )
    except Exception as exc:
        mapped = map_sdk_error(exc, url=client.base_url, cancel_event=cancel_event)
        if mapped is None:
            raise
        if mapped is exc:
            raise
        raise mapped from exc
