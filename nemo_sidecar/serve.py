# serve.py
"""
NeMo Guardrails sidecar — a small localhost HTTP service the main simulator's
``bedrock-nemo`` target calls.

NeMo Guardrails requires Python <3.14 and cannot install in the main project's
3.14 venv. So it runs here, in an isolated Python 3.11 venv, and the main app
talks to it over HTTP (exactly like the aria/firewall targets) — the main app
never imports nemoguardrails.

Endpoints
---------
    GET  /health   -> {"status": "ok", "model": "...", "config": "..."}
    POST /generate {"prompt": "...", "system": "... (optional)"}
                   -> {"blocked": bool, "response": "...", "stop_reason": "..."}

Run
---
    # in a Python 3.11 venv with requirements.txt installed, AWS creds exported:
    NEMOGUARDRAILS_LLM_FRAMEWORK=langchain python serve.py

Bind address is 127.0.0.1 only — this is a local trusted sidecar, never exposed.
"""

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST = os.getenv("NEMO_SIDECAR_HOST", "127.0.0.1")
PORT = int(os.getenv("NEMO_SIDECAR_PORT", "8003"))
CONFIG_PATH = os.getenv(
    "NEMO_CONFIG_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "nemo_config"),
)
MODEL_ID = os.getenv("BEDROCK_MODEL_ID", "amazon.nova-lite-v1:0")

# NeMo's LLMRails is not guaranteed thread-safe; serialize generate() calls. The
# ThreadingHTTPServer still lets /health respond while a /generate is in flight.
_rails = None
_rails_lock = threading.Lock()


def get_rails():
    """Build LLMRails once (loads nemo_config, which registers the Nova provider)."""
    global _rails
    if _rails is None:
        from nemoguardrails import LLMRails, RailsConfig  # imported lazily
        config = RailsConfig.from_path(CONFIG_PATH)
        _rails = LLMRails(config)
    return _rails


def _run_generate(prompt: str, system: str | None = None) -> dict:
    """Run one prompt through the rails and normalize NeMo's reply to a dict."""
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    with _rails_lock:
        result = get_rails().generate(messages=messages)

    # With messages input NeMo returns a single message dict; with a block and
    # enable_rails_exceptions it returns {"role": "exception", "content": {...}}.
    if isinstance(result, dict):
        role = result.get("role")
        content = result.get("content", "")
        if role == "exception":
            reason = "guardrail"
            if isinstance(content, dict):
                reason = content.get("type") or content.get("name") or reason
            return {"blocked": True, "response": _stringify(content), "stop_reason": reason}
        return {"blocked": False, "response": _stringify(content), "stop_reason": "stop"}

    # Fallback: some versions/inputs return a bare string.
    return {"blocked": False, "response": str(result), "stop_reason": "stop"}


def _stringify(content) -> str:
    if isinstance(content, str):
        return content
    try:
        return json.dumps(content, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(content)


class Handler(BaseHTTPRequestHandler):
    # Quieter default logging; the parent logs every request to stderr otherwise.
    def log_message(self, fmt, *args):
        pass

    def _send(self, code: int, body: dict) -> None:
        payload = json.dumps(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path.rstrip("/") == "/health":
            self._send(200, {"status": "ok", "model": MODEL_ID, "config": CONFIG_PATH})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path.rstrip("/") != "/generate":
            self._send(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, json.JSONDecodeError) as e:
            self._send(400, {"error": f"invalid JSON body: {e}"})
            return

        prompt = body.get("prompt")
        if not prompt:
            self._send(400, {"error": "missing 'prompt'"})
            return

        try:
            result = _run_generate(prompt, body.get("system"))
            self._send(200, result)
        except Exception as e:  # surface a clean error to the caller, keep serving
            self._send(500, {"error": f"NeMo generate failed: {type(e).__name__}: {e}"})


def main():
    if os.getenv("NEMOGUARDRAILS_LLM_FRAMEWORK") != "langchain":
        print("[!] NEMOGUARDRAILS_LLM_FRAMEWORK is not set to 'langchain'. The custom "
              "Nova provider needs it; export it before starting the sidecar.")
    print(f"[*] Building NeMo rails from: {CONFIG_PATH}")
    try:
        get_rails()  # fail fast at startup rather than on the first request
        print(f"[+] Rails ready (model: {MODEL_ID}).")
    except Exception as e:
        print(f"[!] Failed to build rails: {type(e).__name__}: {e}")
        print("    Check: nemoguardrails installed, AWS creds exported, config path valid.")
        raise

    server = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"[*] NeMo sidecar listening on http://{HOST}:{PORT}  "
          f"(GET /health, POST /generate)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down NeMo sidecar.")
        server.shutdown()


if __name__ == "__main__":
    main()
