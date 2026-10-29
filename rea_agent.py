#!/usr/bin/env python3
"""
rea-agent: Open-Weight Binary, Driver & Firmware Inspection Agent powered by REA (v6.8.0)

Connects CesarOps fleet open-weight models:
  1. Primary:   kat-coder-v2.5-35b-a3b (http://10.44.0.14:8112/v1 on cesarops4)
  2. Secondary: flint-40b-a2.5b        (http://10.44.0.12:8114/v1 on cesarops2)
  3. Fast:      qwen3.5-9b             (http://10.44.0.12:8088/v1 on cesarops2)

Gives the open-weight model structured tool-calling over the local `rea` v6.8.0 CLI
and companion multi-architecture ELF / Movidius firmware inspection utilities.
"""

import argparse
import json
import os
import shlex
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

FLEET_ENDPOINTS = [
    {
        "name": "kat-coder-v2.5-35b-a3b",
        "base_url": os.environ.get("REA_AGENT_URL", "http://10.44.0.14:8112/v1"),
        "model": os.environ.get("REA_AGENT_MODEL", "kat-coder-v2.5-35b-a3b"),
        "description": "35B-A3B MoE coding & binary/systems specialist on cesarops4",
    },
    {
        "name": "flint-40b-a2.5b",
        "base_url": "http://10.44.0.12:8114/v1",
        "model": "flint-40b-a2.5b",
        "description": "40B-A2.5B MoE deep reasoning & architecture specialist on cesarops2",
    },
    {
        "name": "qwen3.5-9b",
        "base_url": "http://10.44.0.12:8088/v1",
        "model": "qwen3.5-9b",
        "description": "9B fast dense model on cesarops2",
    },
]

REA_BIN = "/usr/local/bin/rea"
MOVIDIUS_BIN = "/data/cargo-target/release/movidius-rust"

SYSTEM_PROMPT = """You are REA-Agent, an expert systems, driver, and firmware reverse-engineering assistant running on the CesarOps compute fleet.
You operate strictly on real binary evidence returned by the `rea` CLI (v6.8.0) and companion ELF/firmware inspection tools.
Never invent, simulate, or hallucinate addresses, symbols, sections, or instruction sequences.

### How to Route Targets with REA:
1. **Linux Kernel Modules (`.ko`)**:
   - Call `rea_command` with `subcommand="inspect-kernel-module"` and `target="/absolute/path/to/module.ko"`.
   - Use `elf_inspect` (`mode="sections"`, `"symbols"`, `"relocs"`, or `"disassemble"`) to inspect `.init.text`, `.text`, `.rodata`, and module parameters.
2. **Movidius Myriad 2 Firmware (`.mvcmd` / `.sparc.elf`) & Graphs (`.graph`)**:
   - If given a `.mvcmd` file, call `movidius_tool` with `action="unpack-fw"` to dissect the boot script into standard 32-bit Little-Endian SPARC V8 (`sparcel`) ELF images.
   - Call `rea_command` with `subcommand="inspect-elf-notes"` on the unpacked `.sparc.elf`.
   - Call `elf_inspect` on `.sparc.elf` (automatically uses SPARC V8 disassembly when machine=2 / EM_SPARC).
   - If given a `.graph` file, call `movidius_tool` with `action="inspect-graph"`.
3. **Rust / Go / .NET / GGUF / Safetensors / Archives / JS Apps**:
   - Rust binary: `rea_command(subcommand="inspect-rust-binary", target=...)`
   - Go binary: `rea_command(subcommand="inspect-go-binary", target=...)`
   - .NET assembly: `rea_command(subcommand="inspect-managed-artifact", target=...)`
   - AI Model (`.gguf` / `.safetensors`): `rea_command(subcommand="inspect-model-artifact", target=...)`
   - Firmware/Archive container: `rea_command(subcommand="inspect-artifact", target=...)`
   - JavaScript/Electron app: `rea_command(subcommand="analyze-javascript-application", target=...)`

Always cite exact evidence IDs (`ev_...`), SHA-256 digests, symbol names, file offsets, and virtual addresses in your final analysis.
"""

TOOLS_SCHEMA = [
    {
        "type": "function",
        "function": {
            "name": "rea_command",
            "description": "Execute a structured REA (Reverse Engineer Anything v6.8.0) CLI subcommand with --json output.",
            "parameters": {
                "type": "object",
                "properties": {
                    "subcommand": {
                        "type": "string",
                        "enum": [
                            "inspect-kernel-module",
                            "inspect-elf-notes",
                            "inspect-rust-binary",
                            "inspect-go-binary",
                            "inspect-artifact",
                            "extract-artifact",
                            "inspect-model-artifact",
                            "inspect-managed-artifact",
                            "inspect-managed-members",
                            "inspect-sqlite-database",
                            "inspect-pe-imports",
                            "inspect-pe-certificates",
                            "analyze-javascript-application",
                            "providers",
                            "capabilities",
                        ],
                        "description": "The REA CLI subcommand to run.",
                    },
                    "target": {
                        "type": "string",
                        "description": "Absolute path to the target binary/file (omit for providers/capabilities).",
                    },
                    "extra_args": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional extra CLI flags (e.g. ['--hash', 'full']).",
                    },
                },
                "required": ["subcommand"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "elf_inspect",
            "description": "Inspect ELF headers, sections, symbols, strings, or disassembly (supports x86_64, aarch64, and SPARC V8 little-endian Myriad 2 firmware).",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute path to the ELF binary, .ko module, or .sparc.elf firmware.",
                    },
                    "mode": {
                        "type": "string",
                        "enum": ["headers", "sections", "symbols", "relocs", "strings", "disassemble"],
                        "description": "Inspection mode.",
                    },
                    "filter_pattern": {
                        "type": "string",
                        "description": "Optional substring/regex filter for symbols, strings, or section/function names.",
                    },
                    "start_address": {
                        "type": "string",
                        "description": "Optional hex start address for disassemble mode (e.g. '0x801a7998').",
                    },
                    "stop_address": {
                        "type": "string",
                        "description": "Optional hex stop address for disassemble mode (e.g. '0x801a7b00').",
                    },
                },
                "required": ["path", "mode"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "movidius_tool",
            "description": "Run movidius-rust firmware unpacker (unpack-fw) or neural graph dissector (inspect-graph).",
            "parameters": {
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["unpack-fw", "inspect-graph"],
                        "description": "Action to perform.",
                    },
                    "path": {
                        "type": "string",
                        "description": "Absolute path to the .mvcmd firmware or .graph file.",
                    },
                    "out_dir": {
                        "type": "string",
                        "description": "Output directory for unpack-fw (optional).",
                    },
                },
                "required": ["action", "path"],
            },
        },
    },
]


def truncate_output(text: str, max_chars: int = 12000) -> str:
    if len(text) <= max_chars:
        return text
    half = max_chars // 2
    return (
        text[:half]
        + f"\n\n... [TRUNCATED {len(text) - max_chars} chars] ...\n\n"
        + text[-half:]
    )


def run_rea_command(args: Dict[str, Any]) -> str:
    subcmd = args.get("subcommand", "")
    target = args.get("target")
    extra = args.get("extra_args") or []
    cmd = [REA_BIN, subcmd]
    if target and subcmd not in ("providers", "capabilities"):
        cmd.append(str(Path(target).resolve()))
    cmd.extend(extra)
    if "--json" not in cmd:
        cmd.append("--json")
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        out = res.stdout.strip() or res.stderr.strip()
        return truncate_output(out)
    except Exception as e:
        return json.dumps({"error": str(e), "command": cmd})


def run_elf_inspect(args: Dict[str, Any]) -> str:
    path = str(Path(args["path"]).resolve())
    mode = args["mode"]
    pattern = args.get("filter_pattern")
    start_addr = args.get("start_address")
    stop_addr = args.get("stop_address")

    if not os.path.exists(path):
        return json.dumps({"error": f"File not found: {path}"})

    is_sparc = path.endswith(".sparc.elf")
    try:
        if mode == "headers":
            cmd = ["readelf", "-h", "-l", path]
        elif mode == "sections":
            cmd = ["readelf", "-S", "-W", path]
        elif mode == "symbols":
            cmd = ["nm", "-n", "-C", path]
        elif mode == "relocs":
            cmd = ["readelf", "-r", "-W", path]
        elif mode == "strings":
            cmd = ["strings", "-n", "5", path]
        elif mode == "disassemble":
            if is_sparc:
                # Check local llvm-objdump first, fallback to cesarops4 llvm-objdump if needed
                objdump_bin = "llvm-objdump"
                cmd = [objdump_bin, "-d", "--triple=sparcel"]
                if start_addr:
                    cmd.append(f"--start-address={start_addr}")
                if stop_addr:
                    cmd.append(f"--stop-address={stop_addr}")
                cmd.append(path)
                if subprocess.run(["which", "llvm-objdump"], capture_output=True).returncode != 0:
                    remote_cmd = (
                        f"llvm-objdump -d --triple=sparcel "
                        + (f"--start-address={shlex.quote(start_addr)} " if start_addr else "")
                        + (f"--stop-address={shlex.quote(stop_addr)} " if stop_addr else "")
                    )
                    with open(path, "rb") as f:
                        p = subprocess.run(
                            ["ssh", "cesarops4", f"cat > /tmp/_rea_sparc.elf && {remote_cmd} /tmp/_rea_sparc.elf"],
                            input=f.read(),
                            capture_output=True,
                            timeout=30,
                        )
                    out = p.stdout.decode("utf-8", errors="replace") or p.stderr.decode("utf-8", errors="replace")
                    if pattern:
                        lines = [ln for ln in out.splitlines() if pattern.lower() in ln.lower()]
                        out = "\n".join(lines)
                    return truncate_output(out)
            else:
                cmd = ["objdump", "-d", "-M", "intel"]
                if start_addr:
                    cmd.append(f"--start-address={start_addr}")
                if stop_addr:
                    cmd.append(f"--stop-address={stop_addr}")
                cmd.append(path)
        else:
            return json.dumps({"error": f"Unsupported mode: {mode}"})

        res = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
        out = res.stdout or res.stderr
        if pattern:
            lines = [ln for ln in out.splitlines() if pattern.lower() in ln.lower()]
            out = "\n".join(lines[:400])
        return truncate_output(out)
    except Exception as e:
        return json.dumps({"error": str(e)})


def run_movidius_tool(args: Dict[str, Any]) -> str:
    action = args["action"]
    path = str(Path(args["path"]).resolve())
    if action == "unpack-fw":
        out_dir = args.get("out_dir") or str(Path(path).parent / "unpacked_elf")
        cmd = [MOVIDIUS_BIN, "unpack-fw", "--firmware", path, "--out-dir", out_dir]
    elif action == "inspect-graph":
        cmd = [MOVIDIUS_BIN, "inspect-graph", "--graph", path]
    else:
        return json.dumps({"error": f"Unknown action: {action}"})
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return truncate_output(res.stdout + res.stderr)
    except Exception as e:
        return json.dumps({"error": str(e)})


def select_endpoint(preferred: Optional[str] = None) -> Dict[str, str]:
    candidates = FLEET_ENDPOINTS
    if preferred:
        candidates = [e for e in FLEET_ENDPOINTS if preferred in e["name"]] + FLEET_ENDPOINTS
    for ep in candidates:
        try:
            req = urllib.request.Request(f"{ep['base_url']}/models", method="GET")
            with urllib.request.urlopen(req, timeout=3) as resp:
                if resp.status == 200:
                    return ep
        except Exception:
            continue
    raise RuntimeError("No open-weight LLM endpoints responded on cesarops4 or cesarops2.")


def chat_completion(ep: Dict[str, str], messages: List[Dict[str, Any]], use_tools: bool = True) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "model": ep["model"],
        "messages": messages,
        "temperature": 0.1,
        "max_tokens": 2048,
    }
    if use_tools:
        payload["tools"] = TOOLS_SCHEMA
        payload["tool_choice"] = "auto"

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"{ep['base_url']}/chat/completions",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=180) as resp:
        return json.loads(resp.read().decode("utf-8"))


def execute_tool_call(name: str, arguments_json: str) -> str:
    try:
        args = json.loads(arguments_json) if isinstance(arguments_json, str) else arguments_json
    except Exception:
        args = {}
    if name == "rea_command":
        return run_rea_command(args)
    if name == "elf_inspect":
        return run_elf_inspect(args)
    if name == "movidius_tool":
        return run_movidius_tool(args)
    return json.dumps({"error": f"Unknown tool: {name}"})


def run_agent(prompt: str, target: Optional[str], model_pref: Optional[str], max_steps: int = 6) -> int:
    ep = select_endpoint(model_pref)
    print(f"[rea-agent] Active Open-Weight Model: {ep['name']} ({ep['base_url']})", file=sys.stderr)

    user_content = prompt
    if target:
        resolved = str(Path(target).resolve())
        user_content = f"Target artifact path: `{resolved}`\n\nTask: {prompt}"

    messages: List[Dict[str, Any]] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_content},
    ]

    # Pre-seed initial REA inspection if a target path is explicitly supplied so the model starts with verified evidence
    if target and os.path.exists(target):
        resolved = str(Path(target).resolve())
        pre_obs = []
        if resolved.endswith(".ko"):
            print(f"[rea-agent] Pre-running `rea inspect-kernel-module {resolved}`...", file=sys.stderr)
            pre_obs.append(("rea inspect-kernel-module", run_rea_command({"subcommand": "inspect-kernel-module", "target": resolved})))
            pre_obs.append(("nm symbols", run_elf_inspect({"path": resolved, "mode": "symbols"})))
        elif resolved.endswith(".sparc.elf"):
            print(f"[rea-agent] Pre-running `rea inspect-elf-notes {resolved}`...", file=sys.stderr)
            pre_obs.append(("rea inspect-elf-notes", run_rea_command({"subcommand": "inspect-elf-notes", "target": resolved})))
            pre_obs.append(("readelf sections", run_elf_inspect({"path": resolved, "mode": "sections"})))
        elif resolved.endswith(".mvcmd"):
            print(f"[rea-agent] Pre-running `movidius-rust unpack-fw {resolved}`...", file=sys.stderr)
            pre_obs.append(("movidius-rust unpack-fw", run_movidius_tool({"action": "unpack-fw", "path": resolved})))
        elif resolved.endswith(".graph"):
            print(f"[rea-agent] Pre-running `movidius-rust inspect-graph {resolved}`...", file=sys.stderr)
            pre_obs.append(("movidius-rust inspect-graph", run_movidius_tool({"action": "inspect-graph", "path": resolved})))
        else:
            print(f"[rea-agent] Pre-running `rea inspect-elf-notes {resolved}`...", file=sys.stderr)
            pre_obs.append(("rea inspect-elf-notes", run_rea_command({"subcommand": "inspect-elf-notes", "target": resolved})))

        obs_text = "\n\n".join(f"### Initial Evidence ({label}):\n```json\n{out}\n```" for label, out in pre_obs)
        messages[-1]["content"] += f"\n\n{obs_text}"

    for step in range(max_steps):
        resp = chat_completion(ep, messages, use_tools=True)
        choice = resp["choices"][0]["message"]
        tool_calls = choice.get("tool_calls") or []

        if not tool_calls:
            content = choice.get("content") or ""
            print(content)
            return 0

        messages.append(choice)
        for tc in tool_calls:
            fn = tc.get("function", {})
            fn_name = fn.get("name", "")
            fn_args = fn.get("arguments", "{}")
            print(f"[rea-agent] Step {step + 1} Tool Call -> {fn_name}({fn_args})", file=sys.stderr)
            result = execute_tool_call(fn_name, fn_args)
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tc.get("id", f"call_{step}"),
                    "name": fn_name,
                    "content": result,
                }
            )

    # Final synthesis call without tools
    resp = chat_completion(ep, messages, use_tools=False)
    print(resp["choices"][0]["message"].get("content", ""))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="rea-agent: Open-Weight Binary, Driver & Firmware Reverse Engineering Agent"
    )
    parser.add_argument("prompt", nargs="?", default="Inspect this target with REA, summarize its architecture, sections, symbols, and key evidence.")
    parser.add_argument("-t", "--target", help="Path to target binary (.ko, .sparc.elf, .mvcmd, .graph, ELF, PE, etc.)")
    parser.add_argument("-m", "--model", help="Preferred fleet model (kat-coder-v2.5-35b-a3b, flint-40b-a2.5b, qwen3.5-9b)")
    parser.add_argument("--list-models", action="store_true", help="List available open-weight models and their live status")
    args = parser.parse_args()

    if args.list_models:
        for ep in FLEET_ENDPOINTS:
            status = "OFFLINE"
            try:
                req = urllib.request.Request(f"{ep['base_url']}/models", method="GET")
                with urllib.request.urlopen(req, timeout=2) as r:
                    if r.status == 200:
                        status = "ONLINE"
            except Exception:
                pass
            print(f"{ep['name']:26s} | {status:7s} | {ep['base_url']} | {ep['description']}")
        return 0

    return run_agent(args.prompt, args.target, args.model)


if __name__ == "__main__":
    sys.exit(main())

