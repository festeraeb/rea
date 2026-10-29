#!/usr/bin/env python3
"""
rea-lemonade-server: Native Lemonade backend server for REA (Reverse Engineer Anything v6.8.0)
+ Open-Weight Fleet Models (kat-coder-v2.5-35b-a3b / flint-40b-a2.5b / qwen3.5-9b).

Launched by `lemond` as a first-class backend (recipe="rea", owned_by="rea"):
  rea-lemonade-server --model {model} --host 127.0.0.1 --port {port} --device {device}
"""

import argparse
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List

# Import REA agent helpers from the same directory
sys.path.insert(0, str(Path(__file__).resolve().parent))
import rea_agent  # noqa: E402

BINARY_EXTENSIONS = {
    ".ko", ".elf", ".so", ".o", ".a", ".exe", ".dll", ".sys", ".dylib",
    ".mvcmd", ".graph", ".gguf", ".safetensors", ".wasm", ".pyc", ".beam",
    ".sqlite", ".db", ".pck", ".bundle", ".apk", ".ipa", ".asar", ".bin", ".hex",
}

BINARY_MAGICS = [
    b"\x7fELF",         # ELF (Linux binaries, .ko drivers, .sparc.elf firmware)
    b"MZ",              # PE/COFF / .NET
    b"\xfe\xed\xfa\xce",  # Mach-O 32
    b"\xfe\xed\xfa\xcf",  # Mach-O 64
    b"\xce\xfa\xed\xfe",  # Mach-O 32 LE
    b"\xcf\xfa\xed\xfe",  # Mach-O 64 LE
    b"\xca\xfe\xba\xbe",  # Universal / Java class
    b"GGUF",            # GGUF model
    b"\x00asm",         # WebAssembly
    b"SQLite format 3", # SQLite
    b"PK\x03\x04",      # ZIP/APK/JAR
    b"UnityFS",         # Unity bundle
    b"GDPC",            # Godot PCK
    b"FOR1",            # Erlang BEAM
]


def is_valid_binary_artifact(path: str) -> bool:
    p = Path(path)
    if not p.is_file():
        return False
    try:
        size = p.stat().st_size
        if size < 16:
            return False
        with open(p, "rb") as f:
            head = f.read(512)
    except Exception:
        return False

    for magic in BINARY_MAGICS:
        if head.startswith(magic):
            return True

    # Check Movidius .mvcmd magic ("MA2x" at offset 20)
    if len(head) >= 24 and head[20:24] in (b"MA2x", b"MA24", b"MA21"):
        return True

    # Check Movidius NCSDK v1 .graph header (version == 2 at offset 36..40, nstages at 240..244)
    if len(head) >= 264 and p.suffix == ".graph":
        version = int.from_bytes(head[36:40], "little")
        nstages = int.from_bytes(head[240:244], "little")
        if version == 2 and 0 < nstages <= 4096:
            return True

    if p.suffix.lower() in BINARY_EXTENSIONS:
        # Reject plain ASCII text files masquerading with an extension
        non_text = sum(1 for b in head if b == 0 or b > 127)
        if non_text > 0:
            return True

    return False


def collect_initial_evidence(model_path: str) -> Dict[str, Any]:
    resolved = str(Path(model_path).resolve())
    obs: List[ Any ] = []
    evidence_id = "ev_rea_initial"
    if resolved.endswith(".ko"):
        raw = rea_agent.run_rea_command({"subcommand": "inspect-kernel-module", "target": resolved})
        obs.append(("rea inspect-kernel-module", raw))
        obs.append(("nm symbols", rea_agent.run_elf_inspect({"path": resolved, "mode": "symbols"})))
    elif resolved.endswith(".sparc.elf"):
        raw = rea_agent.run_rea_command({"subcommand": "inspect-elf-notes", "target": resolved})
        obs.append(("rea inspect-elf-notes", raw))
        obs.append(("readelf sections", rea_agent.run_elf_inspect({"path": resolved, "mode": "sections"})))
    elif resolved.endswith(".mvcmd"):
        raw = rea_agent.run_movidius_tool({"action": "unpack-fw", "path": resolved})
        obs.append(("movidius-rust unpack-fw", raw))
    elif resolved.endswith(".graph"):
        raw = rea_agent.run_movidius_tool({"action": "inspect-graph", "path": resolved})
        obs.append(("movidius-rust inspect-graph", raw))
    else:
        raw = rea_agent.run_rea_command({"subcommand": "inspect-elf-notes", "target": resolved})
        obs.append(("rea inspect-elf-notes", raw))
        obs.append(("readelf headers", rea_agent.run_elf_inspect({"path": resolved, "mode": "headers"})))

    try:
        first_json = json.loads(obs[0][1])
        if isinstance(first_json, dict) and "evidence_id" in first_json:
            evidence_id = first_json["evidence_id"]
    except Exception:
        pass

    return {
        "path": resolved,
        "evidence_id": evidence_id,
        "observations": obs,
    }


class ReaServerContext:
    def __init__(self, model_path: str, device: str):
        self.model_path = model_path
        self.device = device
        self.evidence = collect_initial_evidence(model_path)
        self.requests_served = 0


def run_rea_chat(ctx: ReaServerContext, user_messages: List[Dict[str, Any]]) -> Dict[str, Any]:
    ep = rea_agent.select_endpoint()
    obs_text = "\n\n".join(
        f"### Initial Evidence ({label}):\n```json\n{out}\n```"
        for label, out in ctx.evidence["observations"]
    )

    messages: List[Dict[str, Any]] = [
        {"role": "system", "content": rea_agent.SYSTEM_PROMPT},
    ]
    for i, m in enumerate(user_messages):
        role = m.get("role", "user")
        content = m.get("content", "")
        if isinstance(content, list):
            content = " ".join(
                b.get("text", "") if isinstance(b, dict) else str(b) for b in content
            )
        if i == len(user_messages) - 1 and role == "user":
            content = (
                f"Target artifact path: `{ctx.evidence['path']}`\n\n"
                f"User Question: {content}\n\n{obs_text}"
            )
        messages.append({"role": role, "content": content})

    for step in range(4):
        resp = rea_agent.chat_completion(ep, messages, use_tools=True)
        choice = resp["choices"][0]["message"]
        tool_calls = choice.get("tool_calls") or []
        if not tool_calls:
            return resp
        messages.append(choice)
        for tc in tool_calls:
            fn = tc.get("function", {})
            fn_name = fn.get("name", "")
            fn_args = fn.get("arguments", "{}")
            result = rea_agent.execute_tool_call(fn_name, fn_args)
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tc.get("id", f"call_{step}"),
                    "name": fn_name,
                    "content": result,
                }
            )

    return rea_agent.chat_completion(ep, messages, use_tools=False)


def main() -> int:
    parser = argparse.ArgumentParser(description="Native Lemonade backend server for REA")
    parser.add_argument("--model", required=True, help="Target binary/firmware/driver checkpoint path")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host")
    parser.add_argument("--port", type=int, required=True, help="Bind port")
    parser.add_argument("--device", default="0", help="Device index")
    args = parser.parse_args()

    if not is_valid_binary_artifact(args.model):
        print(
            f"ERROR: '{args.model}' is not a valid binary, driver (.ko), firmware (.mvcmd/.sparc.elf), or model artifact for REA.",
            file=sys.stderr,
        )
        return 1

    ctx = ReaServerContext(args.model, args.device)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *log_args: Any) -> None:
            sys.stderr.write(f"[rea-lemonade] {fmt % log_args}\n")

        def _send_json(self, code: int, payload: Dict[str, Any]) -> None:
            raw = json.dumps(payload).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:
            if self.path.startswith("/health"):
                self._send_json(
                    200,
                    {
                        "status": "ok",
                        "engine": "rea",
                        "artifact": ctx.evidence["path"],
                        "evidence_id": ctx.evidence["evidence_id"],
                    },
                )
            elif self.path.startswith("/v1/models"):
                self._send_json(
                    200,
                    {
                        "object": "list",
                        "data": [
                            {
                                "id": ctx.model_path,
                                "object": "model",
                                "created": int(time.time()),
                                "owned_by": "rea",
                            }
                        ],
                    },
                )
            elif self.path.startswith("/v1/stats"):
                self._send_json(
                    200,
                    {
                        "engine": "rea",
                        "artifact": ctx.evidence["path"],
                        "evidence_id": ctx.evidence["evidence_id"],
                        "requests_served": ctx.requests_served,
                    },
                )
            else:
                self._send_json(404, {"error": "Not Found"})

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
            try:
                req = json.loads(raw_body)
            except Exception:
                req = {}

            if self.path.startswith("/v1/chat/completions") or self.path.startswith("/v1/completions"):
                ctx.requests_served += 1
                user_msgs = req.get("messages")
                if not user_msgs:
                    prompt = req.get("prompt", "Summarize this binary artifact using REA evidence.")
                    user_msgs = [{"role": "user", "content": prompt}]
                try:
                    llm_resp = run_rea_chat(ctx, user_msgs)
                    content = llm_resp["choices"][0]["message"].get("content", "")
                    usage = llm_resp.get("usage") or {
                        "prompt_tokens": 128,
                        "completion_tokens": 128,
                        "total_tokens": 256,
                    }
                    if self.path.startswith("/v1/chat/completions"):
                        self._send_json(
                            200,
                            {
                                "id": f"chatcmpl-rea-{ctx.requests_served}",
                                "object": "chat.completion",
                                "created": int(time.time()),
                                "model": ctx.model_path,
                                "choices": [
                                    {
                                        "index": 0,
                                        "message": {"role": "assistant", "content": content},
                                        "finish_reason": "stop",
                                    }
                                ],
                                "usage": usage,
                            },
                        )
                    else:
                        self._send_json(
                            200,
                            {
                                "id": f"cmpl-rea-{ctx.requests_served}",
                                "object": "text_completion",
                                "created": int(time.time()),
                                "model": ctx.model_path,
                                "choices": [
                                    {
                                        "index": 0,
                                        "text": content,
                                        "finish_reason": "stop",
                                    }
                                ],
                                "usage": usage,
                            },
                        )
                except Exception as e:
                    self._send_json(500, {"error": {"message": str(e)}})
            else:
                self._send_json(404, {"error": "Not Found"})

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    print(
        f"[rea-lemonade] Serving {ctx.evidence['path']} on http://{args.host}:{args.port} (evidence_id={ctx.evidence['evidence_id']})",
        file=sys.stderr,
    )
    httpd.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())

