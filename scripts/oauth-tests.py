"""Test enclave-backed OAuth and resource access; bind to loopback unless --host is set."""

import json
import argparse
import ipaddress
import os
from pathlib import Path
import ssl
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

import oauth_resource

ROOT = Path(__file__).resolve().parent.parent
IMAGE = "quay.io/keycloak/keycloak:26.5.3"


def run(*args, **kwargs):
    return subprocess.run(args, cwd=ROOT, check=True, **kwargs)


def output(*args):
    return run(*args, stdout=subprocess.PIPE, text=True).stdout.strip()


def pki(work, host):
    def openssl(*args):
        run("openssl", *args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

    for name in ["root", "issuer", "server"]:
        openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
                "-out", str(work / f"{name}.key"))
    openssl("req", "-new", "-x509", "-key", str(work / "root.key"), "-days", "7",
            "-subj", "/CN=Huskarl OAuth Test Root", "-out", str(work / "root.pem"),
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    for name, subject, extensions in [
        ("issuer", "Huskarl OAuth Test Issuer",
         "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n"),
        ("server", "localhost",
         "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
         f"extendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:{host}\n"),
    ]:
        (work / f"{name}.ext").write_text(extensions)
        openssl("req", "-new", "-key", str(work / f"{name}.key"), "-subj", f"/CN={subject}",
                "-out", str(work / f"{name}.csr"))
        openssl("x509", "-req", "-in", str(work / f"{name}.csr"),
                "-CA", str(work / "root.pem"), "-CAkey", str(work / "root.key"),
                "-CAcreateserial", "-days", "7", "-sha256", "-extfile", str(work / f"{name}.ext"),
                "-out", str(work / f"{name}.pem"))
    for name in ["root", "issuer"]:
        openssl("x509", "-in", str(work / f"{name}.pem"), "-outform", "DER",
                "-out", str(work / f"{name}.der"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ios-device", action="store_true", help="Run OAuth from the connected iPhone")
    parser.add_argument("--host", default="127.0.0.1", help="Local IPv4 address to bind; use the Mac's LAN address for iPhone tests")
    args = parser.parse_args()
    address = ipaddress.IPv4Address(args.host)
    if not address.is_private or address.is_unspecified:
        parser.error("Use a specific private or loopback IPv4 address")
    if args.ios_device and address.is_loopback:
        parser.error("iPhone tests require --host with this Mac's LAN IPv4 address")
    host = str(address)
    work_root = ROOT / "target" / "oauth-tests"
    work_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=work_root) as directory:
        work = Path(directory)
        pki(work, host)
        resource_secret = secrets.token_urlsafe(32)
        (work / "realm.json").write_text(json.dumps({
            "realm": "huskarl", "enabled": True, "sslRequired": "all",
            "clients": [{
                "clientId": "huskarl-enclave", "enabled": True,
                "protocol": "openid-connect", "publicClient": False,
                "clientAuthenticatorType": "client-x509", "serviceAccountsEnabled": True,
                "standardFlowEnabled": False, "directAccessGrantsEnabled": False,
                "attributes": {
                    "x509.subjectdn": "CN=huskarl-apple-test",
                    "x509.allow.regex.pattern.comparison": "false",
                    "tls.client.certificate.bound.access.tokens": "true",
                },
                "protocolMappers": [{
                    "name": "resource audience", "protocol": "openid-connect",
                    "protocolMapper": "oidc-audience-mapper",
                    "config": {"included.custom.audience": "huskarl-resource",
                               "access.token.claim": "true", "introspection.token.claim": "true"},
                }],
            }, {
                "clientId": "huskarl-resource", "enabled": True,
                "protocol": "openid-connect", "publicClient": False,
                "clientAuthenticatorType": "client-secret", "secret": resource_secret,
                "standardFlowEnabled": False, "directAccessGrantsEnabled": False,
            }],
        }))
        # Mount only the server's credentials, public root, and realm. Keep
        # the test CA signing keys on the host. No admin account is provisioned.
        mounts = []
        for name, destination in [
            ("server.pem", "/test/server.pem"), ("server.key", "/test/server.key"),
            ("root.pem", "/test/root.pem"),
            ("realm.json", "/opt/keycloak/data/import/realm.json"),
        ]:
            (work / name).chmod(0o644)
            mounts.extend(["--mount", f"type=bind,source={work / name},target={destination},readonly"])
        container = output(
            "docker", "run", "--detach", "--rm", "--publish", f"{host}::8443", *mounts,
            IMAGE, "start-dev", "--import-realm", "--http-enabled=false",
            "--hostname-strict=false", "--https-certificate-file=/test/server.pem",
            "--https-certificate-key-file=/test/server.key", "--https-client-auth=request",
            "--truststore-paths=/test/root.pem")
        try:
            address = output("docker", "port", container, "8443/tcp")
            port = address.rsplit(":", 1)[1]
            issuer = f"https://{host}:{port}/realms/huskarl"
            context = ssl.create_default_context(cafile=str(work / "root.pem"))
            deadline = time.monotonic() + 120
            while True:
                try:
                    with urllib.request.urlopen(issuer + "/.well-known/openid-configuration",
                                                context=context, timeout=2) as response:
                        metadata = json.load(response)
                    break
                except (urllib.error.URLError, TimeoutError):
                    if time.monotonic() >= deadline:
                        run("docker", "logs", container)
                        raise RuntimeError("Keycloak did not become ready within 120 seconds")
                    time.sleep(1)
            (work / "metadata.json").write_text(json.dumps(metadata))
            resource, thread = oauth_resource.serve(work, metadata, resource_secret, host)
            (work / "resource-url.txt").write_text(f"https://{host}:{resource.server_port}/resource")
            print(f"Testing OAuth mTLS against {issuer}", flush=True)
            env = dict(os.environ, HUSKARL_OAUTH_TEST_DIR=str(work))
            try:
                if args.ios_device:
                    run("python3", "scripts/ios-device-tests.py", "--oauth-fixture", str(work), env=env)
                else:
                    run("python3", "scripts/signed-tests.py", "urlsession_oauth", env=env)
            finally:
                resource.shutdown()
                resource.server_close()
                thread.join()
                if args.ios_device:
                    # Remove test CA material copied into the generated app.
                    device_work = ROOT / "target" / "ios-oauth-tests"
                    for fixture in [device_work / "oauth-fixture",
                                    device_work / "build/Build/Products/Debug-iphoneos/HuskarlTests.app/oauth-fixture"]:
                        if fixture.exists():
                            shutil.rmtree(fixture)
        finally:
            run("docker", "stop", "--time", "3", container, stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    try:
        main()
    except (subprocess.CalledProcessError, ValueError, RuntimeError, OSError) as error:
        print(f"OAuth tests: {error}", file=sys.stderr)
        sys.exit(1)
