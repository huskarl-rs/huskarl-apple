"""Run native transport and browser-adapter unit tests in an iOS simulator."""

import json
import os
import platform
import shlex
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def run(*args, **kwargs):
    return subprocess.run(args, cwd=ROOT, check=True, **kwargs)


def main():
    result = run("xcrun", "simctl", "list", "devices", "available", "--json",
                 stdout=subprocess.PIPE, text=True)
    requested = os.environ.get("HUSKARL_IOS_SIMULATOR")
    devices = [device for runtime, items in json.loads(result.stdout)["devices"].items()
               if ".iOS-" in runtime for device in items
               if device.get("isAvailable") and (not requested or device["udid"] == requested)]
    devices.sort(key=lambda device: device["state"] != "Booted")
    if not devices:
        raise ValueError("No matching iOS simulator; install an iOS runtime in Xcode")
    device = devices[0]
    if device["state"] != "Booted":
        run("xcrun", "simctl", "boot", device["udid"])
    run("xcrun", "simctl", "bootstatus", device["udid"], "-b")
    target = "aarch64-apple-ios-sim" if platform.machine() == "arm64" else "x86_64-apple-ios"
    runner = "CARGO_TARGET_" + target.upper().replace("-", "_") + "_RUNNER"
    env = dict(os.environ, **{runner: shlex.join(["xcrun", "simctl", "spawn", device["udid"]])})
    common = ["cargo", "test", "--locked", "--features", "urlsession,web-authentication", "--target", target]
    run(*common, "--lib", "urlsession::tests", env=env)
    run(*common, "--lib", "web_authentication::", env=env)
    run(*common, "--test", "urlsession_mtls", env=env)


if __name__ == "__main__":
    try:
        main()
    except (subprocess.CalledProcessError, ValueError, OSError) as error:
        print(f"iOS simulator tests: {error}", file=sys.stderr)
        sys.exit(1)
