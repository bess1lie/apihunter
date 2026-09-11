"""
Minimal security lab API — stdlib only (no external deps).
Demonstrates real detection engines without mocking.
Endpoints:
  GET  /api/users/{id}  -> BOLA heuristic (200 for id=1,2)
  GET  /api/admin       -> 200 without auth (auth bypass heuristic)
  GET  /api/debug       -> Traceback body (info leak)
  POST /api/login       -> 5x 200 without 429 (rate limit heuristic)
  GET  /api/search?q=   -> q=' -> 500 + SQL fragment (injection heuristic)
All responses include CORS wildcard+credentials + Server header for header checks.
"""
import json
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

OPENAPI_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "ApiHunter Lab", "version": "1.0.0"},
    "servers": [{"url": "http://127.0.0.1:8001"}],
    "paths": {
        "/api/users/{id}": {
            "get": {
                "summary": "Get user by id",
                "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}}],
                "responses": {"200": {"description": "OK"}, "404": {"description": "Not found"}},
                "security": [{"bearerAuth": []}],
            }
        },
        "/api/admin": {
            "get": {
                "summary": "Admin panel",
                "responses": {"200": {"description": "OK"}},
                "security": [{"bearerAuth": []}],
            }
        },
        "/api/debug": {
            "get": {
                "summary": "Debug endpoint",
                "responses": {"200": {"description": "OK"}},
            }
        },
        "/api/login": {
            "post": {
                "summary": "Login",
                "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object"}}}},
                "responses": {"200": {"description": "OK"}},
            }
        },
        "/api/search": {
            "get": {
                "summary": "Search",
                "parameters": [{"name": "q", "in": "query", "required": False, "schema": {"type": "string"}}],
                "responses": {"200": {"description": "OK"}, "500": {"description": "Error"}},
            }
        },
        "/api/protected": {
            "get": {
                "summary": "Protected resource (lab demo for authenticated bypass)",
                "responses": {"200": {"description": "OK"}, "401": {"description": "Unauthorized"}},
                "security": [{"bearerAuth": []}],
            }
        },
    },
    "components": {
        "securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}}
    },
}

USERS = {
    "1": {"id": 1, "name": "alice", "email": "alice@lab.local"},
    "2": {"id": 2, "name": "bob", "email": "bob@lab.local", "role": "admin", "extra": "sensitive"},
}


class Handler(BaseHTTPRequestHandler):
    def _set_headers(self, status=200, extra=None):
        self.send_response(status)
        # CORS + security headers for lab (intentionally misconfigured)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, Origin")
        self.send_header("Server", "lab-nginx/1.18")
        # Deliberately missing HSTS / X-Content-Type-Options / X-Frame-Options / CSP
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.end_headers()

    def do_OPTIONS(self):
        self._set_headers(204)

    def do_HEAD(self):
        # Only /openapi.json exists as spec; others 404 for accurate discovery
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path == "/openapi.json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(json.dumps(OPENAPI_SPEC))))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Server", "lab-nginx/1.18")
            self.end_headers()
            return
        self.send_response(404)
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)

        if path == "/openapi.json":
            self._set_headers(200)
            self.wfile.write(json.dumps(OPENAPI_SPEC).encode())
            return
        if path == "/health":
            self._set_headers(200)
            self.wfile.write(b'{"status":"ok"}')
            return
        # BOLA: both ids return 200 with different bodies
        if path.startswith("/api/users/"):
            uid = path.split("/")[-1].split("?")[0]
            # handle q=' injection probe on this path too (for path param injection)
            if "%27" in self.path or "'" in self.path:
                self._set_headers(500)
                self.wfile.write(b"SQL syntax error near ''' at line 1 - sqlite")
                return
            data = USERS.get(uid, {"id": uid, "name": "unknown"})
            self._set_headers(200)
            self.wfile.write(json.dumps(data).encode())
            return
        if path == "/api/admin":
            # Always 200 without auth (auth bypass)
            self._set_headers(200)
            self.wfile.write(b'{"admin": true, "users": ["alice","bob"]}')
            return
        if path == "/api/debug":
            self._set_headers(200)
            body = b"Traceback (most recent call last):\n  File \"/var/www/lab/app.py\", line 42, in do_GET\nInternal debug mode enabled\n"
            self.wfile.write(body)
            return
        if path == "/api/search":
            q = qs.get("q", [""])[0]
            # decode %27
            q_decoded = urllib.parse.unquote(q)
            if "'" in q_decoded:
                self._set_headers(500)
                self.wfile.write(b"SQLSTATE[42000]: Syntax error or access violation: 1064 SQL syntax error near '''")
                return
            self._set_headers(200)
            self.wfile.write(json.dumps({"results": [], "q": q}).encode())
            return
        if path == "/api/protected":
            # Lab demo: always 200 both without and with token → triggers heuristic
            # Real production would return 401 without token, but lab intentionally bypasses
            self._set_headers(200)
            self.wfile.write(b'{"protected": true, "data": "lab-test"}')
            return

        self._set_headers(404)
        self.wfile.write(b'{"error":"not found"}')

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        # consume body
        length = int(self.headers.get("content-length", 0) or 0)
        if length:
            self.rfile.read(length)
        if path == "/api/login":
            self._set_headers(200)
            self.wfile.write(b'{"token":"fake-jwt"}')
            return
        # for other POST, return 404
        self._set_headers(404)
        self.wfile.write(b'{"error":"not found"}')

    def log_message(self, format, *args):
        # quiet except for errors
        pass


if __name__ == "__main__":
    server = HTTPServer(("127.0.0.1", 8001), Handler)
    print("Lab API listening on http://127.0.0.1:8001 (bind localhost only)")
    print("OpenAPI: http://127.0.0.1:8001/openapi.json")
    server.serve_forever()
