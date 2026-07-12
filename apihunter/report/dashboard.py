from __future__ import annotations

from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread


class DashboardHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"<h1>APIHunter Dashboard</h1><p>Running...</p>")

    def log_message(self, format, *args):
        return  # Silence logs


class DashboardServer(Thread):
    def __init__(self, host: str = "0.0.0.0", port: int = 8080):
        super().__init__()
        self.host = host
        self.port = port
        self.server = None
        self.daemon = True

    def run(self):
        self.server = HTTPServer((self.host, self.port), DashboardHandler)
        self.server.serve_forever()

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()


def start_dashboard(host: str = "0.0.0.0", port: int = 8080) -> DashboardServer:
    server = DashboardServer(host, port)
    server.start()
    return server
