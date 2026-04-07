"""
Cullis Agent Console — Unified Agent

A FastAPI web app that provides a generic, role-neutral agent console for
the Cullis federated trust network.  Supports both initiating and receiving
sessions, auto-accept of incoming requests, and optional LLM auto-respond
on received messages.

Reads agent credentials from HashiCorp Vault; connects to a REMOTE broker.
"""
import asyncio
import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field

import httpx
import uvicorn
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

# -- SDK import ----------------------------------------------------------------
sys.path.insert(0, "/app")
from cullis_sdk import CullisClient, load_env_file, cfg  # noqa: E402

# -- Configuration -------------------------------------------------------------

BROKER_URL = os.environ.get("BROKER_URL", "https://broker.cullis.io:8443")
VAULT_ADDR = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
VAULT_TOKEN = os.environ.get("VAULT_TOKEN", "")
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
ORG_ID = os.environ.get("ORG_ID", "agent-org")
AGENT_ID = os.environ.get("AGENT_ID", "agent")
LLM_MODEL = os.environ.get("LLM_MODEL", "claude-sonnet-4-6")
AUTO_ACCEPT = os.environ.get("AUTO_ACCEPT", "true").lower() == "true"
AUTO_RESPOND = os.environ.get("AUTO_RESPOND", "false").lower() == "true"
TERMINATE_KEYWORD = os.environ.get("TERMINATE_KEYWORD", "FINE")
SESSION_TIMEOUT = int(os.environ.get("SESSION_TIMEOUT", "300"))
DISPLAY_NAME = os.environ.get("DISPLAY_NAME", "")
CAPABILITIES = os.environ.get("CAPABILITIES", "chat").split(",")

SYSTEM_PROMPT_FILE = os.environ.get("SYSTEM_PROMPT_FILE", "")
SYSTEM_PROMPT = os.environ.get("SYSTEM_PROMPT", "")

_log = logging.getLogger("cullis.agent")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)

# -- System prompt resolution --------------------------------------------------

_DEFAULT_SYSTEM_PROMPT = """\
You are an AI agent connected to the Cullis federated trust network on behalf \
of {org_id}. You can discover other agents, open secure sessions, and exchange \
messages.

Available tools:
1. discover_agents — search the network for agents by name, description, capability, or org
2. open_session — initiate a secure session with another agent
3. send_message — send an E2E-encrypted message in the active session
4. check_responses — check for new messages from the peer agent
5. check_pending — check for incoming session requests
6. accept_session — accept an incoming session request
7. close_session — close the active session
8. list_sessions — show all active sessions
9. select_session — switch to a different active session

Guidelines:
- When the human asks you to do something, use the appropriate tools.
- Be precise and professional in communications with other agents.
- After sending a message, wait for a response before continuing.
- Use check_responses to poll for replies.
- Report results back to the human clearly.
"""


def _resolve_system_prompt() -> str:
    """Return the system prompt in priority order: file > env > default."""
    if SYSTEM_PROMPT_FILE:
        try:
            with open(SYSTEM_PROMPT_FILE, "r") as f:
                return f.read()
        except Exception as exc:
            _log.warning("Could not read SYSTEM_PROMPT_FILE %s: %s", SYSTEM_PROMPT_FILE, exc)
    if SYSTEM_PROMPT:
        return SYSTEM_PROMPT
    return _DEFAULT_SYSTEM_PROMPT


# -- Data models ---------------------------------------------------------------

@dataclass
class ConsoleMessage:
    role: str           # "human", "assistant", "auto", "system", "tool"
    content: str
    tool_name: str | None = None


@dataclass
class ActiveSession:
    """A single broker session with a remote agent."""
    session_id: str
    peer_agent_id: str
    peer_org_id: str
    role: str  # "initiator" or "responder"
    last_seq: int = -1
    received_messages: list = field(default_factory=list)
    conversation: list[dict] = field(default_factory=list)
    is_processing: bool = False


@dataclass
class AgentSession:
    org_id: str
    agent_id: str
    broker: CullisClient | None = None
    active_session: ActiveSession | None = None   # currently selected session
    all_sessions: dict[str, ActiveSession] = field(default_factory=dict)
    messages: list[ConsoleMessage] = field(default_factory=list)
    llm_conversation: list[dict] = field(default_factory=list)
    is_processing: bool = False


# Single global session (one agent per process)
_session: AgentSession | None = None
_polling_task: asyncio.Task | None = None


# -- Vault helper --------------------------------------------------------------

async def _read_vault_secret(path: str) -> dict:
    """Read a KV-v2 secret from HashiCorp Vault."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{VAULT_ADDR}/v1/{path}",
            headers={"X-Vault-Token": VAULT_TOKEN},
        )
        resp.raise_for_status()
        return resp.json()["data"]["data"]


# -- Auto-respond LLM ---------------------------------------------------------

def _auto_respond_llm(system_prompt: str, conversation: list[dict], new_message: str) -> str:
    """Generate a plain-text LLM response for auto-respond mode (no tools)."""
    import anthropic

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    messages = conversation + [{"role": "user", "content": new_message}]
    response = client.messages.create(
        model=LLM_MODEL,
        max_tokens=1024,
        system=system_prompt,
        messages=messages,
    )
    return response.content[0].text


# -- Background poller ---------------------------------------------------------

async def _background_poller():
    """Poll the broker every 5 s for pending sessions and new messages."""
    while True:
        await asyncio.sleep(5)
        try:
            if not _session or not _session.broker or not _session.broker.token:
                continue
            if _session.is_processing:
                continue

            broker = _session.broker

            # --- Check for pending incoming sessions ---
            try:
                sessions_list = broker.list_sessions()
                for s in sessions_list:
                    sid = s.session_id
                    if (
                        s.status == "pending"
                        and s.target_agent_id == _session.agent_id
                        and sid not in _session.all_sessions
                    ):
                        initiator = s.initiator_agent_id
                        org = s.initiator_org_id

                        if AUTO_ACCEPT:
                            # Auto-accept the session
                            try:
                                broker.accept_session(sid)
                                active = ActiveSession(
                                    session_id=sid,
                                    peer_agent_id=initiator,
                                    peer_org_id=org,
                                    role="responder",
                                )
                                _session.all_sessions[sid] = active
                                if _session.active_session is None:
                                    _session.active_session = active
                                _session.messages.append(ConsoleMessage(
                                    role="system",
                                    content=(
                                        f"Auto-accepted session from {initiator} ({org}). "
                                        f"Session {sid} is now active."
                                    ),
                                ))
                                _log.info("Auto-accepted session %s from %s (%s)", sid, initiator, org)
                            except Exception as exc:
                                _log.warning("Auto-accept failed for %s: %s", sid, exc)
                        else:
                            _session.messages.append(ConsoleMessage(
                                role="system",
                                content=(
                                    f"Incoming session request from {initiator} ({org}). "
                                    f"Use accept_session or check_pending to handle it."
                                ),
                            ))
            except Exception:
                pass

            # --- Check for new messages on all active sessions ---
            for active in list(_session.all_sessions.values()):
                try:
                    messages = broker.poll(active.session_id, after=active.last_seq)
                    for m in messages:
                        active.last_seq = max(active.last_seq, m.seq)
                        text = m.payload.get("text", json.dumps(m.payload)) if isinstance(m.payload, dict) else str(m.payload)
                        sender = m.sender_agent_id

                        active.received_messages.append({"from": sender, "text": text})
                        _session.messages.append(ConsoleMessage(
                            role="system",
                            content=f"[Message from {sender}]: {text}",
                        ))

                        # --- Auto-respond on received sessions ---
                        if (
                            AUTO_RESPOND
                            and ANTHROPIC_API_KEY
                            and active.role == "responder"
                            and not active.is_processing
                        ):
                            active.is_processing = True
                            try:
                                system_prompt = _resolve_system_prompt().format(org_id=_session.org_id)
                                reply = await asyncio.to_thread(
                                    _auto_respond_llm, system_prompt, active.conversation, text,
                                )

                                # Update conversation history
                                active.conversation.append({"role": "user", "content": text})
                                active.conversation.append({"role": "assistant", "content": reply})

                                # Send reply via broker
                                payload = {"type": "message", "text": reply}
                                broker.send(
                                    active.session_id,
                                    _session.agent_id,
                                    payload,
                                    recipient_agent_id=active.peer_agent_id,
                                )

                                _session.messages.append(ConsoleMessage(
                                    role="auto",
                                    content=f"[Auto-reply to {sender}]: {reply}",
                                ))
                                _log.info("Auto-responded on session %s", active.session_id)

                                # Check for termination keyword
                                if TERMINATE_KEYWORD and TERMINATE_KEYWORD in reply:
                                    try:
                                        broker.close_session(active.session_id)
                                        del _session.all_sessions[active.session_id]
                                        if _session.active_session and _session.active_session.session_id == active.session_id:
                                            _session.active_session = None
                                        _session.messages.append(ConsoleMessage(
                                            role="system",
                                            content=f"Session {active.session_id} closed (terminate keyword detected).",
                                        ))
                                    except Exception:
                                        pass
                            except Exception as exc:
                                _log.warning("Auto-respond failed on %s: %s", active.session_id, exc)
                            finally:
                                active.is_processing = False

                except Exception:
                    pass

        except Exception:
            pass


@asynccontextmanager
async def _lifespan(app):
    global _polling_task
    _polling_task = asyncio.create_task(_background_poller())
    yield
    _polling_task.cancel()
    try:
        await _polling_task
    except asyncio.CancelledError:
        pass


# -- FastAPI app ---------------------------------------------------------------

app = FastAPI(title="Cullis Agent Console", lifespan=_lifespan)

templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))


# -- Tool definitions ----------------------------------------------------------

AGENT_TOOLS = [
    {
        "name": "discover_agents",
        "description": (
            "Search the Cullis federated trust network for agents. "
            "Use 'q' for free-text search across agent names, descriptions, org names. "
            "Use 'capabilities' to filter by specific capabilities. "
            "Use 'org_id' to filter by organization. "
            "Use 'pattern' for glob matching on agent_id (e.g. 'chipfactory::*'). "
            "At least one parameter is required. Use q='*' to list all agents."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "q": {
                    "type": "string",
                    "description": "Free-text search across agent name, description, org, agent_id. Use '*' to list all.",
                },
                "capabilities": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Filter by capabilities, e.g. ['order.write', 'manufacturing']",
                },
                "org_id": {
                    "type": "string",
                    "description": "Filter by organization ID",
                },
                "pattern": {
                    "type": "string",
                    "description": "Glob pattern on agent_id, e.g. 'chipfactory::*'",
                },
            },
        },
    },
    {
        "name": "open_session",
        "description": (
            "Open a trusted, policy-evaluated session with another agent "
            "via the Cullis broker. Both organisations' policies are checked."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target_agent_id": {"type": "string", "description": "The target agent ID"},
                "target_org_id": {"type": "string", "description": "The target organisation ID"},
                "capabilities": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Capabilities requested for this session",
                },
            },
            "required": ["target_agent_id", "target_org_id", "capabilities"],
        },
    },
    {
        "name": "send_message",
        "description": (
            "Send a signed and E2E-encrypted message to the peer agent through "
            "the active Cullis session. The message is cryptographically signed "
            "with your private key and encrypted with the peer's public key."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "message": {
                    "type": "string",
                    "description": "The message text to send",
                },
            },
            "required": ["message"],
        },
    },
    {
        "name": "check_responses",
        "description": (
            "Check if the peer agent has sent any new messages in the active session. "
            "Messages are E2E-encrypted and will be decrypted with your private key."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "check_pending",
        "description": (
            "Check if any other agents on the Cullis network have requested "
            "a session with you. Returns a list of pending session requests "
            "that you can accept."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "accept_session",
        "description": (
            "Accept an incoming session request from another agent. "
            "This makes the session active so you can exchange messages."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "The session ID to accept",
                },
            },
            "required": ["session_id"],
        },
    },
    {
        "name": "close_session",
        "description": (
            "Close the current active session with the peer agent. "
            "Use this when the conversation is complete."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "list_sessions",
        "description": (
            "List all active sessions with their peer agents. "
            "Shows session IDs, peers, roles, and message counts."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "select_session",
        "description": (
            "Switch the active session to a different one by session ID. "
            "Use list_sessions first to see available sessions."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "The session ID to switch to",
                },
            },
            "required": ["session_id"],
        },
    },
]


# -- Tool execution ------------------------------------------------------------

def _execute_tool(session: AgentSession, tool_name: str, tool_input: dict) -> str:
    """Execute a broker tool and return the result as a JSON string."""
    broker = session.broker
    if broker is None:
        return json.dumps({"error": "Broker not connected. Use /connect first."})

    try:
        if tool_name == "discover_agents":
            caps = tool_input.get("capabilities")
            org_id = tool_input.get("org_id")
            pattern = tool_input.get("pattern")
            q = tool_input.get("q")
            if not any([caps, org_id, pattern, q]):
                pattern = "*"
            agents = broker.discover(capabilities=caps, org_id=org_id, pattern=pattern, q=q)
            if not agents:
                return json.dumps({"result": "No agents found matching the search criteria."})
            summary = []
            for a in agents:
                desc = getattr(a, "description", "") or ""
                caps_list = getattr(a, "capabilities", []) or []
                caps_str = ", ".join(caps_list)
                line = f"- {a.display_name} ({a.agent_id}) org={a.org_id}"
                if desc:
                    line += f" -- {desc}"
                if caps_str:
                    line += f" [caps: {caps_str}]"
                summary.append(line)
            return json.dumps({"agents_found": len(agents), "agents": "\n".join(summary)})

        elif tool_name == "open_session":
            target_agent = tool_input["target_agent_id"]
            target_org = tool_input["target_org_id"]
            caps = tool_input.get("capabilities", ["chat"])

            session_id = broker.open_session(target_agent, target_org, caps)
            active = ActiveSession(
                session_id=session_id,
                peer_agent_id=target_agent,
                peer_org_id=target_org,
                role="initiator",
            )
            session.all_sessions[session_id] = active
            session.active_session = active

            # Wait for session to be accepted (up to 30 s)
            for _ in range(15):
                sessions_list = broker.list_sessions()
                s = next((x for x in sessions_list if x.session_id == session_id), None)
                if s and s.status == "active":
                    return json.dumps({
                        "result": f"Session {session_id} is now active with {target_agent} ({target_org}).",
                    })
                time.sleep(2)

            return json.dumps({
                "result": (
                    f"Session {session_id} created but target has not accepted yet. "
                    f"Try check_responses later."
                ),
            })

        elif tool_name == "send_message":
            active = session.active_session
            if not active:
                return json.dumps({"error": "No active session. Use open_session or accept_session first."})
            message = tool_input["message"]
            payload = {"type": "message", "text": message}
            broker.send(
                active.session_id,
                session.agent_id,
                payload,
                recipient_agent_id=active.peer_agent_id,
            )
            return json.dumps({"result": f"Message sent to {active.peer_agent_id}."})

        elif tool_name == "check_responses":
            active = session.active_session
            if not active:
                return json.dumps({"error": "No active session."})
            # Read from background poller buffer first
            if active.received_messages:
                texts = list(active.received_messages)
                active.received_messages.clear()
                return json.dumps({"result": texts})
            # Fallback: direct poll
            messages = broker.poll(active.session_id, after=active.last_seq)
            if not messages:
                return json.dumps({"result": "No new messages from the peer."})
            texts = []
            for m in messages:
                active.last_seq = max(active.last_seq, m.seq)
                text = m.payload.get("text", json.dumps(m.payload)) if isinstance(m.payload, dict) else str(m.payload)
                texts.append({"from": m.sender_agent_id, "text": text})
            return json.dumps({"result": texts})

        elif tool_name == "check_pending":
            sessions_list = broker.list_sessions()
            pending = [
                s for s in sessions_list
                if s.status == "pending"
                and s.target_agent_id == session.agent_id
            ]
            if not pending:
                return json.dumps({"result": "No pending session requests."})
            items = [
                {
                    "session_id": s.session_id,
                    "from_agent": s.initiator_agent_id,
                    "from_org": s.initiator_org_id,
                    "capabilities": getattr(s, "requested_capabilities", []),
                }
                for s in pending
            ]
            return json.dumps({"result": items})

        elif tool_name == "accept_session":
            sid = tool_input["session_id"]
            broker.accept_session(sid)
            # Look up session details
            sessions_list = broker.list_sessions()
            s = next((x for x in sessions_list if x.session_id == sid), None)
            if s:
                peer_agent = s.initiator_agent_id
                peer_org = s.initiator_org_id
            else:
                peer_agent = "unknown"
                peer_org = "unknown"
            active = ActiveSession(
                session_id=sid,
                peer_agent_id=peer_agent,
                peer_org_id=peer_org,
                role="responder",
            )
            session.all_sessions[sid] = active
            session.active_session = active
            return json.dumps({"result": f"Session {sid} accepted. Now active with {peer_agent} ({peer_org})."})

        elif tool_name == "close_session":
            active = session.active_session
            if not active:
                return json.dumps({"error": "No active session to close."})
            broker.close_session(active.session_id)
            closed_peer = active.peer_agent_id
            del session.all_sessions[active.session_id]
            session.active_session = None
            return json.dumps({"result": f"Session with {closed_peer} closed successfully."})

        elif tool_name == "list_sessions":
            if not session.all_sessions:
                return json.dumps({"result": "No active sessions."})
            items = []
            for sid, a in session.all_sessions.items():
                items.append({
                    "session_id": sid,
                    "peer": f"{a.peer_agent_id} ({a.peer_org_id})",
                    "role": a.role,
                    "pending_messages": len(a.received_messages),
                    "is_current": session.active_session is not None and session.active_session.session_id == sid,
                })
            return json.dumps({"result": items})

        elif tool_name == "select_session":
            sid = tool_input["session_id"]
            if sid not in session.all_sessions:
                return json.dumps({"error": f"Session {sid} not found. Use list_sessions to see available sessions."})
            session.active_session = session.all_sessions[sid]
            peer = session.active_session.peer_agent_id
            return json.dumps({"result": f"Switched to session {sid} with {peer}."})

        else:
            return json.dumps({"error": f"Unknown tool: {tool_name}"})

    except Exception as e:
        _log.exception("Tool execution error: %s", tool_name)
        return json.dumps({"error": str(e)})


# -- LLM interaction with tool loop -------------------------------------------

def _call_llm_with_tools(session: AgentSession, user_message: str) -> str:
    """Call Claude with tools, execute tool calls in a loop, return final text."""
    import anthropic

    if not ANTHROPIC_API_KEY:
        return "Error: ANTHROPIC_API_KEY not configured."

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    system = _resolve_system_prompt().format(org_id=session.org_id)

    session.llm_conversation.append({"role": "user", "content": user_message})
    messages = list(session.llm_conversation)

    max_iterations = 10

    for _ in range(max_iterations):
        response = client.messages.create(
            model=LLM_MODEL,
            max_tokens=2048,
            system=system,
            tools=AGENT_TOOLS,
            messages=messages,
        )

        # Collect text and tool_use blocks
        text_parts = []
        tool_calls = []
        for block in response.content:
            if block.type == "text":
                text_parts.append(block.text)
            elif block.type == "tool_use":
                tool_calls.append(block)

        if not tool_calls:
            final_text = "\n".join(text_parts)
            session.llm_conversation.append({"role": "assistant", "content": response.content})
            return final_text

        # Add assistant message with all content blocks
        session.llm_conversation.append({"role": "assistant", "content": response.content})
        messages = list(session.llm_conversation)

        # Execute each tool and add results
        tool_results = []
        for tc in tool_calls:
            session.messages.append(ConsoleMessage(
                role="tool",
                content=f"Calling {tc.name}...",
                tool_name=tc.name,
            ))
            result = _execute_tool(session, tc.name, tc.input)
            session.messages.append(ConsoleMessage(
                role="tool",
                content=f"{tc.name} -> {result}",
                tool_name=tc.name,
            ))
            tool_results.append({
                "type": "tool_result",
                "tool_use_id": tc.id,
                "content": result,
            })

        session.llm_conversation.append({"role": "user", "content": tool_results})
        messages = list(session.llm_conversation)

    return "Reached maximum tool iterations. Please try again."


# -- Routes --------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Serve the agent console chat UI."""
    connected = (
        _session is not None
        and _session.broker is not None
        and _session.broker.token is not None
    )
    msgs = _session.messages if _session else []
    return templates.TemplateResponse(
        request=request,
        name="console.html",
        context={
            "org_id": ORG_ID,
            "agent_id": AGENT_ID,
            "connected": connected,
            "messages": msgs,
        },
    )


@app.post("/connect")
async def connect():
    """Read cert+key from Vault, create CullisClient, login to remote broker."""
    global _session

    try:
        # Read credentials from Vault
        org_ca_secret = await _read_vault_secret("secret/data/org-ca")
        agent_secret = await _read_vault_secret("secret/data/agent")

        ca_cert_pem = org_ca_secret["ca_cert_pem"]
        cert_pem = agent_secret["cert_pem"]
        key_pem = agent_secret["private_key_pem"]

        _log.info("Loaded credentials from Vault for %s/%s", ORG_ID, AGENT_ID)

        # Create CullisClient and authenticate
        broker = CullisClient(BROKER_URL, verify_tls=False)

        display = DISPLAY_NAME or AGENT_ID
        try:
            broker.register(
                AGENT_ID, ORG_ID, display, CAPABILITIES,
            )
        except Exception:
            pass  # Already registered

        broker.login_from_pem(AGENT_ID, ORG_ID, cert_pem, key_pem)
        _log.info("Authenticated to broker at %s", BROKER_URL)

        _session = AgentSession(
            org_id=ORG_ID,
            agent_id=AGENT_ID,
            broker=broker,
        )
        _session.messages.append(ConsoleMessage(
            role="system",
            content=f"Connected as {AGENT_ID} ({ORG_ID}) to broker at {BROKER_URL}.",
        ))

        return JSONResponse({"status": "connected", "agent_id": AGENT_ID, "org_id": ORG_ID})

    except Exception as e:
        _log.exception("Connect failed")
        return JSONResponse({"status": "error", "detail": str(e)}, status_code=500)


@app.post("/send")
async def send(request: Request):
    """Receive human message, call Claude with tools, execute tools, return reply."""
    global _session

    if not _session or not _session.broker:
        return JSONResponse({"error": "Not connected to broker"}, status_code=400)

    form = await request.form()
    user_msg = str(form.get("message", "")).strip()
    if not user_msg:
        return JSONResponse({"error": "Empty message"}, status_code=400)

    if _session.is_processing:
        return JSONResponse({"error": "Already processing a request"}, status_code=429)

    _session.is_processing = True
    _session.messages.append(ConsoleMessage(role="human", content=user_msg))

    try:
        reply = _call_llm_with_tools(_session, user_msg)
        _session.messages.append(ConsoleMessage(role="assistant", content=reply))
    except Exception as e:
        _log.exception("LLM error")
        reply = f"Error: {e}"
        _session.messages.append(ConsoleMessage(role="system", content=reply))
    finally:
        _session.is_processing = False

    return JSONResponse({"reply": reply, "message_count": len(_session.messages)})


@app.get("/messages")
async def get_messages():
    """Return conversation history as JSON (for HTMX polling)."""
    if not _session:
        return JSONResponse({"messages": [], "connected": False, "processing": False})

    active = _session.active_session
    msgs = [
        {"role": m.role, "content": m.content, "tool_name": m.tool_name}
        for m in _session.messages
    ]
    return JSONResponse({
        "messages": msgs,
        "connected": _session.broker is not None and _session.broker.token is not None,
        "processing": _session.is_processing,
        "session_id": active.session_id if active else None,
        "target": active.peer_agent_id if active else None,
        "session_count": len(_session.all_sessions),
    })


@app.post("/disconnect")
async def disconnect():
    """Close all sessions and broker client."""
    global _session

    if _session and _session.broker:
        for active in _session.all_sessions.values():
            try:
                _session.broker.close_session(active.session_id)
            except Exception:
                pass
        try:
            _session.broker.close()
        except Exception:
            pass

    _session = None
    return JSONResponse({"status": "disconnected"})


# -- Entrypoint ----------------------------------------------------------------

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
