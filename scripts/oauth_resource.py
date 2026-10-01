"""Test-only HTTPS resource server enforcing RFC 8705 certificate binding.

Token validity is checked by Keycloak introspection, not by decoding unverified
JWTs. This fixture is deliberately small and is not a production API server.
"""

import base64
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import ssl
import threading
import urllib.error
import urllib.parse
import urllib.request


def serve(work, metadata, secret, host="127.0.0.1"):
    upstream_tls = ssl.create_default_context(cafile=str(work / "root.pem"))
    credential = base64.b64encode(f"huskarl-resource:{secret}".encode()).decode()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            # Never log access tokens, headers, or introspection responses.
            pass

        def do_GET(self):
            allowed = False
            certificate = self.connection.getpeercert(binary_form=True)
            authorization = self.headers.get("Authorization", "")
            if self.path == "/resource" and certificate and authorization.startswith("Bearer "):
                token = authorization.removeprefix("Bearer ")
                request = urllib.request.Request(
                    metadata["introspection_endpoint"],
                    data=urllib.parse.urlencode({"token": token}).encode(),
                    headers={"Authorization": f"Basic {credential}",
                             "Content-Type": "application/x-www-form-urlencoded"})
                try:
                    with urllib.request.urlopen(request, context=upstream_tls, timeout=5) as response:
                        claims = json.load(response)
                    audience = claims.get("aud", [])
                    if isinstance(audience, str):
                        audience = [audience]
                    fingerprint = base64.urlsafe_b64encode(hashlib.sha256(certificate).digest()).rstrip(b"=").decode()
                    bound = claims.get("cnf", {}).get("x5t#S256", "")
                    allowed = (claims.get("active") is True
                               and claims.get("iss") == metadata["issuer"]
                               and "huskarl-resource" in audience
                               and isinstance(bound, str)
                               and hmac.compare_digest(bound, fingerprint))
                except (urllib.error.URLError, TimeoutError, ValueError):
                    # Any unavailable or invalid introspection result denies access.
                    allowed = False
            body = b"certificate-bound resource\n" if allowed else b"unauthorized\n"
            self.send_response(200 if allowed else 401)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Type", "text/plain")
            self.send_header("Connection", "close")
            if not allowed:
                self.send_header("WWW-Authenticate", 'Bearer error="invalid_token"')
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer((host, 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(work / "server.pem"), str(work / "server.key"))
    context.load_verify_locations(cafile=str(work / "root.pem"))
    context.verify_mode = ssl.CERT_OPTIONAL
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread
