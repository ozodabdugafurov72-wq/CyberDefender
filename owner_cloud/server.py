from __future__ import annotations

import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from owner_cloud.app import Application, Request
from owner_cloud.config import Config


HOST = os.getenv("CYBERDEFENDER_OWNER_HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", os.getenv("CYBERDEFENDER_OWNER_PORT", "8080")))


def build_handler(application: Application):
    class Handler(BaseHTTPRequestHandler):
        server_version = "CyberDefender"
        sys_version = ""

        def log_message(self, format, *args):
            return

        def _serve(self) -> None:
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = 0
            if length < 0 or length > 16 * 1024:
                length = 0
            body = self.rfile.read(length) if length else b""
            request = Request(
                method=self.command,
                target=self.path,
                headers={key: value for key, value in self.headers.items()},
                body=body,
                peer_ip=self.client_address[0] if self.client_address else "",
            )
            response = application.handle(request)
            self.send_response(response.status)
            for name, value in response.headers:
                self.send_header(name, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(response.body)

        do_GET = _serve
        do_POST = _serve
        do_HEAD = _serve

    return Handler


def serve() -> None:
    config = Config.from_environment()
    application = Application(config)
    server = ThreadingHTTPServer((HOST, PORT), build_handler(application))
    server.serve_forever()


if __name__ == "__main__":
    serve()
