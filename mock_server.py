import json
from http.server import BaseHTTPRequestHandler, HTTPServer


class MockAPIHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/openapi.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            spec = {
                "openapi": "3.0.0",
                "info": {"title": "Mock API", "version": "1.0.0"},
                "paths": {
                    "/users": {
                        "get": {
                            "responses": {"200": {"description": "OK"}}
                        }
                    },
                    "/status": {
                        "get": {
                            "responses": {"200": {"description": "OK"}}
                        }
                    }
                }
            }
            self.wfile.write(json.dumps(spec).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_HEAD(self):
        self.do_GET()

if __name__ == "__main__":
    server = HTTPServer(('localhost', 8000), MockAPIHandler)
    print("Serving Mock API on http://localhost:8000")
    server.serve_forever()
