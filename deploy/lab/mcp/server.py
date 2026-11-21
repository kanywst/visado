"""A tiny MCP server for the lab, standard library only.

Speaks the Streamable HTTP transport on POST /mcp with JSON responses and no
sessions: initialize, ping, tools/list and tools/call. Its two tools work on
an in-memory file store: read_file returns a file's text and delete_file
removes it. Every tools/call it receives is logged to stdout, so the lab can
show which calls reached it and which visado stopped at the gateway.
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FILES = {
    "/data/report.pdf": "Q3 report: revenue 4.2M, churn 3.1%. Internal only.",
    "/etc/passwd": "root:x:0:0:root:/root:/bin/sh",
}

TOOLS = [
    {
        "name": "read_file",
        "description": "Read a file from the store.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "delete_file",
        "description": "Delete a file from the store.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
]


def text(value, error=False):
    return {"content": [{"type": "text", "text": value}], "isError": error}


def call_tool(name, arguments):
    path = arguments.get("path", "")
    if name == "read_file":
        if path in FILES:
            return text(FILES[path])
        return text(f"no such file: {path}", error=True)
    if name == "delete_file":
        if FILES.pop(path, None) is not None:
            return text(f"deleted {path}")
        return text(f"no such file: {path}", error=True)
    return None


def handle(message):
    method = message.get("method")
    params = message.get("params") or {}
    if method == "initialize":
        return {
            "protocolVersion": params.get("protocolVersion", "2025-06-18"),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "lab-files", "version": "1.0.0"},
        }
    if method == "ping":
        return {}
    if method == "tools/list":
        return {"tools": TOOLS}
    if method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments") or {}
        print(
            json.dumps({"mcp_tool_call": name, "arguments": arguments}),
            flush=True,
        )
        return call_tool(name, arguments)
    return None


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, body=None):
        data = b"" if body is None else json.dumps(body).encode()
        self.send_response(status)
        if body is not None:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        if self.path != "/mcp":
            self.reply(404)
            return
        length = int(self.headers.get("Content-Length", "0"))
        try:
            message = json.loads(self.rfile.read(length))
        except ValueError:
            self.reply(400, {"jsonrpc": "2.0", "id": None,
                             "error": {"code": -32700, "message": "parse error"}})
            return
        if not isinstance(message, dict):
            self.reply(400, {"jsonrpc": "2.0", "id": None,
                             "error": {"code": -32600, "message": "batches are not supported"}})
            return
        if "id" not in message:
            # A notification or a response: accepted, nothing to return.
            self.reply(202)
            return
        result = handle(message)
        if result is None:
            self.reply(200, {"jsonrpc": "2.0", "id": message["id"],
                             "error": {"code": -32601, "message": "method not found"}})
            return
        self.reply(200, {"jsonrpc": "2.0", "id": message["id"], "result": result})

    def do_GET(self):
        # No server-initiated stream.
        self.reply(405)

    def do_DELETE(self):
        self.reply(405)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
