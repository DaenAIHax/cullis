"""
Cullis — Demo agent helpers.

Infrastructure (auth, crypto, messaging) is in the cullis_sdk package.
This module provides demo-specific logic: LLM integration, run_initiator,
run_responder, and the order negotiation loop.

Import from cullis_sdk for production use:
    from cullis_sdk import CullisClient
"""
import json
import os
import time

# Re-export SDK infrastructure for backward compatibility
from cullis_sdk import CullisClient, cfg, log, log_msg
from cullis_sdk._logging import CYAN, GREEN, YELLOW, RED, GRAY

# Keep BrokerClient as alias for existing demo agents
BrokerClient = CullisClient


# ─────────────────────────────────────────────
# LLM
# ─────────────────────────────────────────────

def ask_llm(system_prompt: str, conversation: list[dict], new_message: str) -> str:
    llm_base_url = os.environ.get("LLM_BASE_URL", "").strip()
    messages = conversation + [{"role": "user", "content": new_message}]

    if llm_base_url:
        from openai import OpenAI
        llm_client = OpenAI(
            base_url=llm_base_url,
            api_key=os.environ.get("LLM_API_KEY", "not-needed"),
        )
        model = os.environ.get("LLM_MODEL", "gpt-4o")
        response = llm_client.chat.completions.create(
            model=model,
            max_tokens=1024,
            messages=[{"role": "system", "content": system_prompt}] + messages,
        )
        return response.choices[0].message.content
    else:
        import anthropic
        llm_client = anthropic.Anthropic(api_key=cfg("ANTHROPIC_API_KEY"))
        response = llm_client.messages.create(
            model=os.environ.get("LLM_MODEL", "claude-sonnet-4-6"),
            max_tokens=1024,
            system=system_prompt,
            messages=messages,
        )
        return response.content[0].text


# ─────────────────────────────────────────────
# WebSocket helper
# ─────────────────────────────────────────────

def _open_ws(broker: CullisClient, agent_id: str):
    """Open an authenticated WebSocket connection. Returns None if unavailable."""
    try:
        ws = broker.connect_websocket()
        log(agent_id, "WebSocket connesso.", GREEN)
        return ws
    except Exception as e:
        log(agent_id, f"WebSocket non disponibile: {e}", YELLOW)
        return None


def _contains_fine(text: str, last_n: int = 5) -> bool:
    return "FINE" in text.upper().split()[-last_n:]


# ─────────────────────────────────────────────
# Shared message processing
# ─────────────────────────────────────────────

def _process_received_message(
    broker: CullisClient,
    agent_id: str,
    session_id: str,
    received_text: str,
    sender_id: str,
    system_prompt: str,
    conversation: list[dict],
    turns: int,
    max_turns: int,
    payload_type: str,
    extra_payload: dict,
) -> tuple[bool, int]:
    """Process a received message: generate response, send, update state."""
    log(agent_id, f"Ricevuto da {sender_id}:", YELLOW)
    log_msg("IN", {"text": received_text})

    if _contains_fine(received_text):
        log(agent_id, "Conversazione terminata dall'altro agente.", GREEN)
        try:
            broker.close_session(session_id)
        except Exception:
            pass
        return False, turns

    reply = ask_llm(system_prompt, conversation, received_text)
    log(agent_id, "Rispondo:", CYAN)
    log_msg("OUT", {"text": reply})

    payload = {"type": payload_type, "text": reply}
    payload.update(extra_payload)
    broker.send(session_id, agent_id, payload, recipient_agent_id=sender_id)
    conversation.append({"role": "user",      "content": received_text})
    conversation.append({"role": "assistant", "content": reply})
    turns += 1

    if _contains_fine(reply):
        log(agent_id, "Conversazione conclusa.", GREEN)
        try:
            broker.close_session(session_id)
        except Exception:
            pass
        return False, turns

    if turns >= max_turns:
        log(agent_id, f"Limite massimo di turni raggiunto ({max_turns}), chiudo sessione.", YELLOW)
        try:
            broker.close_session(session_id)
        except Exception:
            pass
        return False, turns

    return True, turns


# ─────────────────────────────────────────────
# Runner: INITIATOR
# ─────────────────────────────────────────────

def run_initiator(broker: CullisClient, agent_id: str, max_turns: int,
                  poll_interval: int, system_prompt: str) -> None:
    target_agent_id = os.environ.get("TARGET_AGENT_ID")
    target_org_id   = os.environ.get("TARGET_ORG_ID")
    order_id        = cfg("ORDER_ID", "ORD-2026-001")
    order_item      = cfg("ORDER_ITEM", "zinc-plated M8 bolts")
    order_quantity  = cfg("ORDER_QUANTITY", "1000")

    if not target_agent_id:
        needed_caps = cfg("CAPABILITIES", "order.read,order.write").split(",")
        log(agent_id, f"TARGET_AGENT_ID non impostato — cerco nel network {needed_caps}...", CYAN)
        candidates = broker.discover(needed_caps)
        if not candidates:
            log(agent_id, "Nessun agente trovato con le capabilities richieste.", RED)
            return
        chosen          = candidates[0]
        target_agent_id = chosen.agent_id
        target_org_id   = chosen.org_id
        log(agent_id,
            f"Trovati {len(candidates)} candidati — connessione a "
            f"{target_agent_id} ({chosen.display_name}, org: {target_org_id})", GREEN)

    conversation: list[dict] = []
    turns = 0
    session_id: str | None = None
    last_seq = -1

    existing = broker.list_sessions()
    resumed  = next(
        (s for s in existing
         if s.target_agent_id == target_agent_id and s.status == "active"),
        None,
    )

    if resumed:
        session_id = resumed.session_id
        log(agent_id, f"Sessione attiva ripristinata: {session_id}", YELLOW)
        queued   = broker.poll(session_id, after=-1)
        last_seq = max((m.seq for m in queued), default=-1)
        if queued:
            for msg in queued:
                received_text = msg.payload.get("text", json.dumps(msg.payload))
                ok, turns = _process_received_message(
                    broker, agent_id, session_id,
                    received_text, msg.sender_agent_id,
                    system_prompt, conversation, turns, max_turns,
                    "order_negotiation", {"order_id": order_id},
                )
                if not ok:
                    return
        else:
            log(agent_id, "Inbox vuota — invio richiesta ordine iniziale.", CYAN)
            initial_user_msg = (
                f"Devo piazzare l'ordine {order_id}: {order_quantity} {order_item}. "
                f"Prepara la richiesta formale al fornitore."
            )
            first_message = ask_llm(system_prompt, [], initial_user_msg)
            log_msg("OUT", {"text": first_message})
            broker.send(session_id, agent_id,
                        {"type": "order_request", "text": first_message, "order_id": order_id},
                        recipient_agent_id=target_agent_id)
            conversation = [
                {"role": "user",      "content": initial_user_msg},
                {"role": "assistant", "content": first_message},
            ]
            turns = 1
    else:
        log(agent_id, f"Apertura sessione verso {target_agent_id}...", CYAN)
        import httpx
        for attempt in range(10):
            try:
                session_id = broker.open_session(
                    target_agent_id, target_org_id, ["order.write"]
                )
                break
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 404 and attempt < 9:
                    log(agent_id, f"Target non ancora registrato, retry ({attempt+1}/10)...", GRAY)
                    time.sleep(3)
                else:
                    raise

        log(agent_id, f"Sessione creata: {session_id}", GREEN)
        log(agent_id, "Attendo che il responder accetti...", GRAY)

        for _ in range(30):
            sessions = broker.list_sessions()
            s = next((x for x in sessions if x.session_id == session_id), None)
            if s and s.status == "active":
                break
            time.sleep(poll_interval)
        else:
            log(agent_id, "Timeout: il responder non ha accettato la sessione.", RED)
            return

        log(agent_id, "Sessione attiva — avvio negoziazione.", GREEN)
        initial_user_msg = (
            f"Devo piazzare l'ordine {order_id}: {order_quantity} {order_item}. "
            f"Prepara la richiesta formale al fornitore, chiedendo disponibilità, "
            f"prezzo unitario, tempi di consegna e condizioni di pagamento."
        )
        first_message = ask_llm(system_prompt, [], initial_user_msg)
        log(agent_id, "Invio richiesta ordine:", CYAN)
        log_msg("OUT", {"text": first_message})
        broker.send(session_id, agent_id,
                    {"type": "order_request", "text": first_message, "order_id": order_id},
                    recipient_agent_id=target_agent_id)
        conversation = [
            {"role": "user",      "content": initial_user_msg},
            {"role": "assistant", "content": first_message},
        ]
        turns    = 1
        last_seq = -1

    ws = _open_ws(broker, agent_id)
    if ws is not None:
        try:
            for msg in ws:
                if msg.get("type") != "new_message":
                    continue
                if msg.get("session_id") != session_id:
                    continue
                m = broker.decrypt_payload(msg["message"], session_id=session_id)
                received_text = m["payload"].get("text", json.dumps(m["payload"]))
                ok, turns = _process_received_message(
                    broker, agent_id, session_id,
                    received_text, m["sender_agent_id"],
                    system_prompt, conversation, turns, max_turns,
                    "order_negotiation", {"order_id": order_id},
                )
                if not ok:
                    return
        except Exception as e:
            log(agent_id, f"WS interrotto: {e}", YELLOW)
        finally:
            try:
                ws.close()
            except Exception:
                pass
    else:
        while turns < max_turns:
            time.sleep(poll_interval)
            messages = broker.poll(session_id, after=last_seq, poll_interval=poll_interval)
            for msg in messages:
                last_seq = msg.seq
                received_text = msg.payload.get("text", json.dumps(msg.payload))
                ok, turns = _process_received_message(
                    broker, agent_id, session_id,
                    received_text, msg.sender_agent_id,
                    system_prompt, conversation, turns, max_turns,
                    "order_negotiation", {"order_id": order_id},
                )
                if not ok:
                    return
        log(agent_id, f"Limite di {max_turns} turni raggiunto.", YELLOW)


# ─────────────────────────────────────────────
# Runner: RESPONDER
# ─────────────────────────────────────────────

_SESSION_TIMEOUT = int(os.environ.get("SESSION_TIMEOUT", "300"))


def _responder_handle_session(broker: CullisClient, agent_id: str,
                               session_id: str, max_turns: int,
                               poll_interval: int, system_prompt: str) -> None:
    """Handle a single session from start to finish."""
    conversation: list[dict] = []
    turns = 0
    session_start = time.monotonic()
    last_activity = time.monotonic()

    queued   = broker.poll(session_id, after=-1)
    last_seq = max((m.seq for m in queued), default=-1)
    for msg in queued:
        last_activity = time.monotonic()
        received_text = msg.payload.get("text", json.dumps(msg.payload))
        ok, turns = _process_received_message(
            broker, agent_id, session_id,
            received_text, msg.sender_agent_id,
            system_prompt, conversation, turns, max_turns,
            "order_response", {},
        )
        if not ok:
            return

    while True:
        time.sleep(poll_interval)

        elapsed = time.monotonic() - session_start
        idle = time.monotonic() - last_activity
        if elapsed > _SESSION_TIMEOUT or idle > _SESSION_TIMEOUT:
            log(agent_id, f"Sessione {session_id} scaduta ({int(elapsed)}s) — chiudo.", YELLOW)
            try:
                broker.close_session(session_id)
            except Exception:
                pass
            return

        sessions = broker.list_sessions()
        current  = next((s for s in sessions if s.session_id == session_id), None)
        if current is None or current.status == "closed":
            log(agent_id, f"Sessione {session_id} chiusa — pronto per il prossimo.", GREEN)
            return

        messages = broker.poll(session_id, after=last_seq, poll_interval=poll_interval)
        for msg in messages:
            last_seq = msg.seq
            last_activity = time.monotonic()
            received_text = msg.payload.get("text", json.dumps(msg.payload))
            ok, turns = _process_received_message(
                broker, agent_id, session_id,
                received_text, msg.sender_agent_id,
                system_prompt, conversation, turns, max_turns,
                "order_response", {},
            )
            if not ok:
                return

        if turns >= max_turns:
            log(agent_id, f"Limite turni raggiunto per sessione {session_id} — chiudo.", YELLOW)
            try:
                broker.close_session(session_id)
            except Exception:
                pass
            return


def run_responder(broker: CullisClient, agent_id: str, max_turns: int,
                  poll_interval: int, system_prompt: str) -> None:
    """Infinite loop: accept sessions, handle conversation, restart."""
    log(agent_id, "Online — in attesa di sessioni in arrivo (Ctrl+C per fermare).", CYAN)

    # Close stale active sessions from previous runs
    active    = broker.list_sessions(status="active")
    my_active = [s for s in active if s.target_agent_id == agent_id]
    for s in my_active:
        try:
            broker.close_session(s.session_id)
            log(agent_id, f"Chiusa sessione precedente: {s.session_id}", YELLOW)
        except Exception:
            pass

    while True:
        try:
            ws = _open_ws(broker, agent_id)
        except Exception:
            ws = None

        if ws is not None:
            try:
                pending    = broker.list_sessions(status="pending")
                my_pending = [s for s in pending if s.target_agent_id == agent_id]
                if my_pending:
                    session_id = my_pending[0].session_id
                    broker.accept_session(session_id)
                    log(agent_id, f"Sessione accettata (pre-WS): {session_id}", GREEN)
                    ws.close()
                    _responder_handle_session(broker, agent_id, session_id,
                                              max_turns, poll_interval, system_prompt)
                    continue

                log(agent_id, "In ascolto su WebSocket...", GRAY)
                for msg in ws:
                    if msg.get("type") == "session_pending":
                        session_id = msg["session_id"]
                        initiator  = msg.get("initiator_agent_id", "unknown")
                        broker.accept_session(session_id)
                        log(agent_id, f"Nuova sessione da {initiator}: {session_id}", GREEN)
                        ws.close()
                        _responder_handle_session(broker, agent_id, session_id,
                                                  max_turns, poll_interval, system_prompt)
                        break
            except KeyboardInterrupt:
                raise
            except Exception as e:
                log(agent_id, f"Errore WS: {e} — switching a polling.", YELLOW)
            finally:
                try:
                    ws.close()
                except Exception:
                    pass
        else:
            time.sleep(poll_interval)
            pending    = broker.list_sessions(status="pending")
            my_pending = [s for s in pending if s.target_agent_id == agent_id]
            if my_pending:
                session_id = my_pending[0].session_id
                initiator  = my_pending[0].initiator_agent_id
                broker.accept_session(session_id)
                log(agent_id, f"Nuova sessione da {initiator}: {session_id}", GREEN)
                _responder_handle_session(broker, agent_id, session_id,
                                          max_turns, poll_interval, system_prompt)
