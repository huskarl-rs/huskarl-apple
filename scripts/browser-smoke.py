"""Build a macOS browser-login app and run a disposable loopback-only Keycloak."""
import argparse
import json
import http.client
import os
from pathlib import Path
import plistlib
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
WORK = ROOT / "target/browser-smoke"
IMAGE = "quay.io/keycloak/keycloak:26.5.3"


def run(*args, **kwargs):
    return subprocess.run(args, cwd=ROOT, check=True, **kwargs)


def output(*args):
    return run(*args, stdout=subprocess.PIPE, text=True).stdout.strip()


def build():
    app = WORK / "HuskarlBrowserSmoke.app"
    binary_dir = app / "Contents/MacOS"
    binary_dir.mkdir(parents=True, exist_ok=True)
    run("cargo", "build", "--manifest-path", "examples/browser-login/rust/Cargo.toml",
        env=dict(os.environ, CARGO_TARGET_DIR=str(ROOT / "target")))
    run("xcrun", "swiftc", "-parse-as-library", "examples/browser-login/App.swift",
        "-import-objc-header", "examples/browser-login/Bridge.h",
        "-module-cache-path", str(WORK / "swift-cache"),
        str(ROOT / "target/debug/libhuskarl_browser_smoke.a"),
        "-framework", "Security", "-framework", "CoreFoundation",
        "-framework", "Foundation", "-framework", "AuthenticationServices",
        "-framework", "AppKit", "-o", str(binary_dir / "HuskarlBrowserSmoke"))
    (app / "Contents/Info.plist").write_bytes(plistlib.dumps({
        "CFBundleIdentifier": "io.huskarl.browser-smoke",
        "CFBundleExecutable": "HuskarlBrowserSmoke", "CFBundleName": "Huskarl Browser Smoke",
        "CFBundlePackageType": "APPL", "CFBundleVersion": "1",
        "CFBundleShortVersionString": "1.0", "NSPrincipalClass": "NSApplication",
        "LSMinimumSystemVersion": "14.0",
        "NSAppTransportSecurity": {"NSAllowsLocalNetworking": True},
        "CFBundleURLTypes": [{"CFBundleURLSchemes": ["io.huskarl.browser-smoke"]}],
    }))
    run("codesign", "--force", "--sign", "-", str(app))
    return binary_dir / "HuskarlBrowserSmoke"


def cancellation_passed(text):
    return (text.count("BROWSER_SMOKE browser_started") == 3
            and text.count("BROWSER_SMOKE completed: The user or caller cancelled authentication.") == 2
            and text.count("BROWSER_SMOKE dropped_pending_session") == 1
            and "BROWSER_SMOKE cancellation_sequence_finished" in text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-only", action="store_true")
    parser.add_argument("--check-cancellation", action="store_true", help="Automatically cancel, drop, and restart sessions without logging in")
    args = parser.parse_args()
    binary = build()
    if args.build_only:
        return
    with tempfile.TemporaryDirectory(dir=WORK) as directory:
        realm = Path(directory) / "realm.json"
        realm.write_text(json.dumps({
            "realm": "huskarl-browser", "enabled": True, "sslRequired": "none",
            "clients": [{"clientId": "huskarl-browser", "enabled": True,
                "protocol": "openid-connect", "publicClient": True,
                "standardFlowEnabled": True, "directAccessGrantsEnabled": False,
                "redirectUris": ["io.huskarl.browser-smoke:/callback"],
                "attributes": {"pkce.code.challenge.method": "S256"}}],
            "users": [{"username": "huskarl", "enabled": True,
                "emailVerified": True, "firstName": "Huskarl", "lastName": "Test",
                "email": "huskarl@example.invalid", "requiredActions": [],
                "credentials": [{"type": "password", "value": "huskarl-test-only", "temporary": False}]}],
        }))
        realm.chmod(0o644)
        container = output("docker", "run", "--detach", "--rm", "--publish", "127.0.0.1::8080",
            "--mount", f"type=bind,source={realm},target=/opt/keycloak/data/import/realm.json,readonly",
            IMAGE, "start-dev", "--import-realm", "--hostname-strict=false")
        app = None
        try:
            port = output("docker", "port", container, "8080/tcp").rsplit(":", 1)[1]
            issuer = f"http://127.0.0.1:{port}/realms/huskarl-browser"
            deadline = time.monotonic() + 120
            while True:
                try:
                    with urllib.request.urlopen(issuer + "/.well-known/openid-configuration", timeout=2):
                        break
                except (urllib.error.URLError, TimeoutError, ConnectionError, http.client.HTTPException):
                    if time.monotonic() >= deadline:
                        raise RuntimeError("Keycloak did not become ready")
                    time.sleep(1)
            log_path = WORK / "app.log"
            print(f"Ready: {issuer}\nApp log: {log_path}\nQuit the app to clean up Keycloak.", flush=True)
            with log_path.open("w") as log:
                app = subprocess.Popen([str(binary)], cwd=ROOT,
                    env=dict(os.environ, HUSKARL_BROWSER_ISSUER=issuer,
                        HUSKARL_BROWSER_CANCEL_CHECK="1" if args.check_cancellation else "0"), stdout=log, stderr=log)
                if app.wait(timeout=60 if args.check_cancellation else None) != 0:
                    raise RuntimeError(f"Smoke app failed; inspect {log_path}")
            if args.check_cancellation:
                text = log_path.read_text()
                if not cancellation_passed(text):
                    raise RuntimeError(f"Cancellation sequence failed; inspect {log_path}")
                print("Explicit cancel, drop, and restart checks passed.", flush=True)
        finally:
            if app is not None and app.poll() is None:
                app.terminate()
                app.wait(timeout=10)
            run("docker", "stop", "--time", "3", container, stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
