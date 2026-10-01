"""Build and run the signed macOS native OAuth/DPoP session example."""
import argparse
import datetime
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
WORK = ROOT / "target/native-session"


def run(*args, **kwargs):
    return subprocess.run(args, cwd=ROOT, check=True, **kwargs)


def authorized(value, patterns):
    return bool(value) and "*" not in value and any(
        value == pattern or (pattern.endswith("*") and value.startswith(pattern[:-1]))
        for pattern in patterns)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-only", action="store_true")
    parser.add_argument("--unsigned", action="store_true", help="Compile-only ad-hoc bundle; requires --build-only")
    args = parser.parse_args()
    if args.unsigned and not args.build_only:
        parser.error("--unsigned requires --build-only; enclave access needs provisioning")
    if sys.platform != "darwin":
        parser.error("macOS and Xcode are required")
    profile_path = None
    claims = None
    bundle_id = "io.huskarl.native-session"
    identity = "-"
    group = None
    if not args.unsigned:
        identity = os.environ.get("HUSKARL_SIGNING_IDENTITY")
        profile_path = os.environ.get("HUSKARL_PROVISIONING_PROFILE")
        if not identity or not profile_path:
            raise ValueError("Set HUSKARL_SIGNING_IDENTITY and HUSKARL_PROVISIONING_PROFILE (see mise.local.toml.example)")
        profile_path = Path(profile_path).expanduser().resolve()
        profile = plistlib.loads(run("security", "cms", "-D", "-i", str(profile_path), stdout=subprocess.PIPE).stdout)
        if profile["ExpirationDate"] <= datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None):
            raise ValueError("Provisioning profile has expired")
        allowed = profile["Entitlements"]
        profile_app = allowed["com.apple.application-identifier"]
        prefix, _, default_bundle = profile_app.partition(".")
        bundle_id = os.environ.get("HUSKARL_BUNDLE_ID", default_bundle)
        app_id = f"{prefix}.{bundle_id}"
        group = os.environ.get("HUSKARL_ACCESS_GROUP", os.environ.get("HUSKARL_TEST_ACCESS_GROUP", app_id))
        if not authorized(app_id, [profile_app]) or not authorized(group, allowed.get("keychain-access-groups", [])):
            raise ValueError("Bundle identifier and access group must be concrete and profile-authorized")
        claims = {"com.apple.application-identifier": app_id,
                  "com.apple.developer.team-identifier": allowed["com.apple.developer.team-identifier"],
                  "keychain-access-groups": [group]}
    app = WORK / "HuskarlNativeSession.app"
    contents = app / "Contents"
    binary = contents / "MacOS/HuskarlNativeSession"
    binary.parent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, CARGO_TARGET_DIR=str(ROOT / "target"), MACOSX_DEPLOYMENT_TARGET="14.0")
    run("cargo", "build", "--locked", "--manifest-path", "examples/native-session/rust/Cargo.toml", env=env)
    run("xcrun", "swiftc", "-parse-as-library", "examples/native-session/App.swift",
        "-import-objc-header", "examples/native-session/Bridge.h",
        "-module-cache-path", str(WORK / "swift-cache"),
        str(ROOT / "target/debug/libhuskarl_native_session.a"),
        "-framework", "Security", "-framework", "CoreFoundation", "-framework", "Foundation",
        "-framework", "AuthenticationServices", "-framework", "AppKit", "-o", str(binary), env=env)
    (contents / "Info.plist").write_bytes(plistlib.dumps({
        "CFBundleIdentifier": bundle_id, "CFBundleExecutable": binary.name,
        "CFBundleName": "Huskarl Native Session", "CFBundlePackageType": "APPL",
        "CFBundleVersion": "1", "CFBundleShortVersionString": "1.0",
        "LSMinimumSystemVersion": "14.0", "NSPrincipalClass": "NSApplication",
    }))
    signing_args = []
    embedded = contents / "embedded.provisionprofile"
    if claims:
        entitlements = WORK / "entitlements.plist"
        entitlements.write_bytes(plistlib.dumps(claims))
        shutil.copy2(profile_path, embedded)
        signing_args = ["--entitlements", str(entitlements)]
    elif embedded.exists():
        embedded.unlink()  # A compile-only rebuild must not carry a stale profile.
    run("codesign", "--force", "--sign", identity, *signing_args, str(app))
    run("codesign", "--verify", "--strict", str(app))
    print(f"Built {app}", flush=True)
    if not args.build_only:
        # Run the bundle executable directly so the app receives this shell's
        # provider configuration. Launch Services does not inherit it reliably.
        run(str(binary), env=dict(os.environ, HUSKARL_ACCESS_GROUP=group))


if __name__ == "__main__":
    try:
        main()
    except (subprocess.CalledProcessError, ValueError, KeyError, OSError) as error:
        print(f"Native session example: {error}", file=sys.stderr)
        sys.exit(1)
