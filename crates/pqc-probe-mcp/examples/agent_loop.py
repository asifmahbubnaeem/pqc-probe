#!/usr/bin/env python3
"""A hand-written agent loop: a local Ollama model + the pqc-probe MCP server.

No libraries beyond the Python standard library, on purpose: every step an agent framework
hides is visible here.

  1. Start the MCP server as a child process and do the MCP handshake over stdio.
  2. Ask it for its tools and hand their JSON schemas to the model.
  3. Loop: send the conversation to the model; if it asks for tools, call them through MCP
     and append the results; stop when it answers in plain text or after --max-steps.
  4. Write every step to a JSONL trace, so you can see where the model went wrong.

Usage:
  python3 agent_loop.py --server ./target/release/pqc-probe-mcp \
      "Does cloudflare.com support post-quantum key exchange over TLS?"

Needs Ollama running locally with a tool-calling model (default qwen3:8b).
"""

import argparse
import json
import subprocess
import sys
import time
import urllib.request


NUDGE = (
    "Your last tool call failed. If you meant to try again, call the tool now. "
    "Otherwise, give your final answer."
)


class McpClient:
    """Minimal MCP client over stdio: newline-delimited JSON-RPC 2.0."""

    def __init__(self, cmd):
        self.proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr, text=True
        )
        self.next_id = 0
        init = self.request(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "agent-loop", "version": "0.1"},
            },
        )
        self.instructions = init.get("instructions", "")
        self.notify("notifications/initialized")

    def notify(self, method, params=None):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def request(self, method, params=None):
        self.next_id += 1
        msg = {"jsonrpc": "2.0", "id": self.next_id, "method": method}
        if params is not None:
            msg["params"] = params
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()
        while True:
            line = self.proc.stdout.readline()
            if not line:
                raise RuntimeError("MCP server exited")
            reply = json.loads(line)
            if reply.get("id") != self.next_id:
                continue  # a notification or log message from the server
            if "error" in reply:
                raise RuntimeError(f"MCP protocol error: {reply['error']}")
            return reply["result"]

    def close(self):
        self.proc.stdin.close()
        self.proc.wait(timeout=10)


def to_ollama_tools(mcp_tools):
    """MCP tool list -> the `tools` field of Ollama's /api/chat."""
    out = []
    for t in mcp_tools:
        schema = dict(t.get("inputSchema") or {"type": "object", "properties": {}})
        schema.pop("$schema", None)
        out.append(
            {
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t.get("description", ""),
                    "parameters": schema,
                },
            }
        )
    return out


def chat(ollama_url, model, messages, tools, think):
    body = json.dumps(
        {"model": model, "messages": messages, "tools": tools, "stream": False, "think": think}
    ).encode()
    req = urllib.request.Request(
        f"{ollama_url}/api/chat", data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=600) as r:
        return json.load(r)


def tool_result_text(result, summary_only=False):
    """Join the text blocks of an MCP CallToolResult, marking errors for the model.

    With summary_only, keep just the first block: pqc-probe-mcp puts its plain-text verdict
    there and the full JSON report after it. A small model rarely needs the report, and every
    token of it is prompt the model must read on the next step.
    """
    blocks = [b.get("text", "") for b in result.get("content", []) if b.get("type") == "text"]
    if summary_only:
        blocks = blocks[:1]
    text = "\n".join(blocks)
    return ("TOOL ERROR: " + text) if result.get("isError") else text


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("question")
    ap.add_argument("--server", default="pqc-probe-mcp", help="path to the pqc-probe-mcp binary")
    ap.add_argument("--server-arg", action="append", default=[], help="extra argument for the server (repeatable)")
    ap.add_argument("--model", default="qwen3:8b")
    ap.add_argument("--ollama-url", default="http://localhost:11434")
    ap.add_argument("--max-steps", type=int, default=6)
    ap.add_argument("--think", action="store_true", help="let qwen3 think before answering (slower)")
    ap.add_argument("--trace", default="agent_trace.jsonl")
    ap.add_argument("--summary-only", action="store_true",
                    help="send the model only the verdict lines of each tool result, not the full JSON report")
    args = ap.parse_args()

    mcp = McpClient([args.server, *args.server_arg])
    tools = mcp.request("tools/list")["tools"]
    messages = [
        {
            "role": "system",
            "content": "You answer questions about servers' post-quantum cryptography support using the tools. "
            "Base every claim on a tool result. If a tool refuses or fails, say so plainly. "
            "When you need a tool, call it; never say you will call it later.\n\n"
            + mcp.instructions,
        },
        {"role": "user", "content": args.question},
    ]

    with open(args.trace, "w") as trace:

        def log(**event):
            event["t"] = round(time.time(), 3)
            trace.write(json.dumps(event) + "\n")
            trace.flush()

        log(kind="start", model=args.model, question=args.question, tools=[t["name"] for t in tools],
            summary_only=args.summary_only)
        last_tool_failed = False
        nudged = False
        for step in range(1, args.max_steps + 1):
            t0 = time.time()
            reply = chat(args.ollama_url, args.model, messages, to_ollama_tools(tools), args.think)
            msg = reply["message"]
            calls = msg.get("tool_calls") or []
            log(
                kind="model",
                step=step,
                seconds=round(time.time() - t0, 2),
                content=msg.get("content", ""),
                tool_calls=calls,
                prompt_tokens=reply.get("prompt_eval_count"),
                output_tokens=reply.get("eval_count"),
            )
            messages.append({k: v for k, v in msg.items() if k in ("role", "content", "tool_calls")})

            if not calls:
                # Small models often answer a tool error with "I will retry..." and no tool call.
                # Nudge once; if it still doesn't call a tool, take its text as the answer.
                if last_tool_failed and not nudged:
                    nudged = True
                    messages.append({"role": "user", "content": NUDGE})
                    log(kind="nudge", step=step)
                    continue
                print(msg.get("content", "").strip())
                log(kind="done", step=step)
                break

            for call in calls:
                fn = call["function"]
                name, arguments = fn["name"], fn.get("arguments") or {}
                if isinstance(arguments, str):  # some models send a JSON string
                    arguments = json.loads(arguments)
                print(f"[step {step}] calling {name} {json.dumps(arguments)}", file=sys.stderr)
                t1 = time.time()
                result = mcp.request("tools/call", {"name": name, "arguments": arguments})
                text = tool_result_text(result, args.summary_only)
                log(kind="tool", step=step, name=name, arguments=arguments,
                    is_error=bool(result.get("isError")), seconds=round(time.time() - t1, 2), result=text[:4000])
                messages.append({"role": "tool", "tool_name": name, "content": text})
                last_tool_failed = bool(result.get("isError"))
        else:
            print(f"Stopped after {args.max_steps} steps without a final answer (see {args.trace}).")
            log(kind="gave_up")

    mcp.close()


if __name__ == "__main__":
    main()
