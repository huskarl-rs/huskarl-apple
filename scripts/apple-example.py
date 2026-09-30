"""Build and launch the SwiftUI/Rust Keychain example on macOS or in an iOS simulator."""
import argparse
import json
import datetime
import shutil
import os
from pathlib import Path
import platform
import plistlib
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
BUNDLE_ID = "io.huskarl.simulator-example"
GROUP = "HUSKARLSIM." + BUNDLE_ID


def run(*args, **kwargs):
    return subprocess.run(args, cwd=ROOT, check=True, **kwargs)


def output(*args):
    return run(*args, stdout=subprocess.PIPE, text=True).stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--macos", action="store_true")
    parser.add_argument("--build-only", action="store_true")
    parser.add_argument("--verify", action="store_true", help="Check store/load/clear across processes")
    args = parser.parse_args()
    if args.build_only and args.verify:
        parser.error("--build-only and --verify cannot be combined")
    if sys.platform != "darwin":
        parser.error("Xcode and macOS are required")
    arch = "arm64" if platform.machine() == "arm64" else "x86_64"
    target = "aarch64-apple-ios-sim" if arch == "arm64" else "x86_64-apple-ios"
    group, bundle_id = GROUP, BUNDLE_ID
    service = "io.huskarl.simulator-example"
    sdk_name = "macosx" if args.macos else "iphonesimulator"
    sdk = output("xcrun", "--sdk", sdk_name, "--show-sdk-path")
    if args.macos:
        target = "aarch64-apple-darwin" if arch == "arm64" else "x86_64-apple-darwin"
        service = "io.huskarl.macos-example"
        identity = os.environ.get("HUSKARL_SIGNING_IDENTITY")
        profile_path = os.environ.get("HUSKARL_PROVISIONING_PROFILE")
        if not identity or not profile_path:
            raise ValueError("Set HUSKARL_SIGNING_IDENTITY and HUSKARL_PROVISIONING_PROFILE in mise.local.toml")
        profile_path = str(Path(profile_path).expanduser().resolve())
        profile = plistlib.loads(run("security", "cms", "-D", "-i", profile_path,
                                    stdout=subprocess.PIPE).stdout)
        if profile["ExpirationDate"] <= datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None):
            raise ValueError("Provisioning profile has expired")
        allowed = profile["Entitlements"]
        profile_app = allowed["com.apple.application-identifier"]
        prefix, _, default_bundle = profile_app.partition(".")
        bundle_id = os.environ.get("HUSKARL_BUNDLE_ID", default_bundle)
        app_id = f"{prefix}.{bundle_id}"
        group = os.environ.get("HUSKARL_TEST_ACCESS_GROUP", app_id)
        def authorized(value, patterns):
            return "*" not in value and any(value == p or
                (p.endswith("*") and value.startswith(p[:-1])) for p in patterns)
        if not bundle_id or not group or not authorized(app_id, [profile_app]) or not authorized(group, allowed.get("keychain-access-groups", [])):
            raise ValueError("Bundle identifier and access group must be concrete and profile-authorized")
    work = ROOT / "target" / ("macos-example" if args.macos else "ios-example")
    app = work / "HuskarlExample.app"
    app.mkdir(parents=True, exist_ok=True)
    contents = app / "Contents" if args.macos else app
    binary_dir = contents / "MacOS" if args.macos else app
    binary_dir.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, CARGO_TARGET_DIR=str(work / "rust"),
               HUSKARL_EXAMPLE_ACCESS_GROUP=group, HUSKARL_EXAMPLE_SERVICE=service, IPHONEOS_DEPLOYMENT_TARGET="18.0")
    run("cargo", "build", "--locked", "--manifest-path", "examples/apple/rust/Cargo.toml",
        "--target", target, env=env)
    simulator_link_args = []
    if not args.macos:
        # Simulator entitlements live in Mach-O sections, not the host signature.
        simulated = work / "simulated-entitlements.plist"
        simulated.write_bytes(plistlib.dumps({
            "application-identifier": group, "keychain-access-groups": [group],
        }))
        for value in ["-sectcreate", "__TEXT", "__entitlements", str(simulated)]:
            simulator_link_args.extend(["-Xlinker", value])
    run("xcrun", "--sdk", sdk_name, "swiftc", "-parse-as-library",
        "-sdk", sdk, "-target", f"{arch}-apple-macosx14.0" if args.macos else f"{arch}-apple-ios18.0-simulator",
        "-module-cache-path", str(work / "swift-cache"),
        "-import-objc-header", "examples/apple/Bridge.h", "examples/apple/App.swift",
        str(work / "rust" / target / "debug" / "libhuskarl_apple_example.a"),
        "-framework", "Security", "-framework", "CoreFoundation",
        *simulator_link_args, "-o", str(binary_dir / "HuskarlExample"))
    info = {
        "CFBundleIdentifier": bundle_id, "CFBundleExecutable": "HuskarlExample",
        "CFBundleName": "Huskarl", "CFBundlePackageType": "APPL",
        "CFBundleVersion": "1", "CFBundleShortVersionString": "1.0",
        "CFBundleSupportedPlatforms": ["iPhoneSimulator"],
        "MinimumOSVersion": "18.0", "LSRequiresIPhoneOS": True,
        "UIDeviceFamily": [1, 2], "UILaunchScreen": {},
        "UIApplicationSceneManifest": {"UIApplicationSupportsMultipleScenes": False},
    }
    if args.macos:
        for key in ["MinimumOSVersion", "LSRequiresIPhoneOS", "UIDeviceFamily", "UILaunchScreen", "UIApplicationSceneManifest"]:
            info.pop(key)
        info.update(CFBundleSupportedPlatforms=["MacOSX"], LSMinimumSystemVersion="14.0", NSPrincipalClass="NSApplication")
    (contents / "Info.plist").write_bytes(plistlib.dumps(info))
    entitlements = work / "entitlements.plist"
    claims = {"application-identifier": group, "keychain-access-groups": [group]}
    if args.macos:
        claims = {"com.apple.application-identifier": app_id,
                  "com.apple.developer.team-identifier": allowed["com.apple.developer.team-identifier"],
                  "keychain-access-groups": [group]}
        shutil.copy2(profile_path, contents / "embedded.provisionprofile")
    entitlements.write_bytes(plistlib.dumps(claims))
    signing_args = ["--entitlements", str(entitlements)] if args.macos else []
    run("codesign", "--force", "--sign", identity if args.macos else "-", *signing_args, str(app))
    print(f"Built {app}", flush=True)
    if args.build_only:
        return
    if args.macos:
        run("codesign", "--verify", "--strict", str(app))
        if args.verify:
            for action, expected in [(2, 0), (1, 2), (0, 1), (2, 0), (0, 0)]:
                result = output(str(binary_dir / "HuskarlExample"), "--check", str(action), str(expected))
                print(result, flush=True)
                if f"HUSKARL_CHECK action={action} result={expected}" not in result:
                    raise ValueError("macOS persistence check failed")
            print("Store, reload in a fresh process, clear, and absence checks passed.")
        else:
            run("open", "-n", str(app))
        return
    devices = json.loads(output("xcrun", "simctl", "list", "devices", "available", "--json"))
    candidates = [d for runtime, items in devices["devices"].items()
                  if ".iOS-" in runtime for d in items if d.get("isAvailable")]
    requested = os.environ.get("HUSKARL_IOS_SIMULATOR")
    if requested:
        candidates = [d for d in candidates if d["udid"] == requested]
    candidates.sort(key=lambda d: d["state"] != "Booted")
    if not candidates:
        raise ValueError("No matching iOS simulator. Install an iOS runtime in Xcode Settings > Components, "
                         "then create a device in Window > Devices and Simulators.")
    device = candidates[0]
    udid = device["udid"]
    if device["state"] != "Booted":
        run("xcrun", "simctl", "boot", udid)
    run("xcrun", "simctl", "bootstatus", udid, "-b")
    run("xcrun", "simctl", "install", udid, str(app))
    if args.verify:
        for action, expected in [(2, 0), (1, 2), (0, 1), (2, 0), (0, 0)]:
            result = output("xcrun", "simctl", "launch", "--terminate-running-process",
                            "--console", udid, BUNDLE_ID, "--check", str(action), str(expected))
            print(result, flush=True)
            if f"HUSKARL_CHECK action={action} result={expected}" not in result:
                raise ValueError("Simulator persistence check failed")
        print("Store, reload in a fresh process, clear, and absence checks passed.")
    else:
        developer = Path(output("xcode-select", "-p"))
        locations = [developer / "Applications" / "Simulator.app",
                     developer.parent / "Applications" / "Simulator.app",
                     developer.parent / "Applications" / "DeviceHub.app"]
        simulator = next((path for path in locations if path.exists()), None)
        if simulator is None:
            raise ValueError("Simulator or Device Hub was not found in the selected Xcode installation")
        run("open", "-a", str(simulator))
        run("xcrun", "simctl", "launch", "--terminate-running-process", udid, BUNDLE_ID)


if __name__ == "__main__":
    try:
        main()
    except (subprocess.CalledProcessError, ValueError, OSError) as error:
        print(f"Apple example: {error}", file=sys.stderr)
        sys.exit(1)
