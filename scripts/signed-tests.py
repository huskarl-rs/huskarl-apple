"""Run provisioned macOS tests. Configuration comes from mise.local.toml via env."""

import argparse
import datetime
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TESTS = ["keychain_lifecycle", "keychain_storage", "load_or_generate"]


def required(name):
    value = os.environ.get(name, "").strip()
    if not value:
        raise ValueError(f"Set {name} in mise.local.toml (see mise.local.toml.example)")
    return value


def run(*args, **kwargs):
    return subprocess.run(args, cwd=ROOT, check=True, **kwargs)


def authorized(value, patterns):
    # Provisioning profiles allow exact claims or a trailing wildcard.
    return any(value == p or (p.endswith("*") and value.startswith(p[:-1]))
               for p in patterns)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cleanup", action="store_true", help="Preview leftover enclave test keys")
    parser.add_argument("--delete", action="store_true", help="Delete keys selected by --cleanup")
    parser.add_argument("tests", nargs="*", metavar="TEST",
                        help="default: " + ", ".join(DEFAULT_TESTS)
                        + "; also available: access_groups, user_presence")
    args = parser.parse_args()
    if (args.delete and not args.cleanup) or (args.cleanup and args.tests):
        parser.error("--delete requires --cleanup; cleanup does not accept test names")
    tests = args.tests or DEFAULT_TESTS
    if any(t not in DEFAULT_TESTS + ["access_groups", "user_presence"] for t in tests):
        parser.error("unknown test executable")
    if sys.platform != "darwin":
        raise ValueError("Signed tests require macOS")
    identity = required("HUSKARL_SIGNING_IDENTITY")
    profile_path = Path(required("HUSKARL_PROVISIONING_PROFILE")).expanduser().resolve()
    profile = plistlib.loads(run("security", "cms", "-D", "-i", str(profile_path),
                                stdout=subprocess.PIPE).stdout)
    if profile["ExpirationDate"] <= datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None):
        raise ValueError("Provisioning profile has expired")
    allowed = profile["Entitlements"]
    profile_app = allowed["com.apple.application-identifier"]
    prefix, _, default_bundle = profile_app.partition(".")
    bundle_id = os.environ.get("HUSKARL_BUNDLE_ID", default_bundle)
    app_id = f"{prefix}.{bundle_id}"
    if not bundle_id or "*" in app_id or not authorized(app_id, [profile_app]):
        raise ValueError("Set HUSKARL_BUNDLE_ID to a concrete identifier authorized by the profile")
    group = os.environ.get("HUSKARL_TEST_ACCESS_GROUP", app_id)
    groups = [group]
    test_env = dict(os.environ, HUSKARL_TEST_ACCESS_GROUP=group)
    if "access_groups" in tests:
        a, b = required("HUSKARL_TEST_ACCESS_GROUP_A"), required("HUSKARL_TEST_ACCESS_GROUP_B")
        if a == b:
            raise ValueError("The access_groups test requires two distinct groups")
        groups.extend([a, b])
    if args.cleanup:
        groups.extend(os.environ[name] for name in
                      ["HUSKARL_TEST_ACCESS_GROUP_A", "HUSKARL_TEST_ACCESS_GROUP_B"]
                      if os.environ.get(name))
    groups = list(dict.fromkeys(groups))
    if any(not g or "*" in g or not authorized(g, allowed.get("keychain-access-groups", []))
           for g in groups):
        raise ValueError("Every access group must be concrete and authorized by the profile")
    work_root = ROOT / "target" / "signing"
    work_root.mkdir(parents=True, exist_ok=True)
    # Separate bundles prevent concurrent task invocations from replacing a running binary.
    with tempfile.TemporaryDirectory(prefix="tests-", dir=work_root) as temporary:
        work = Path(temporary)
        if "," in str(work):
            raise ValueError("The linker command requires a repository path without commas")
        info = work / "Info.plist"
        info.write_bytes(plistlib.dumps({
            "CFBundleIdentifier": bundle_id, "CFBundleExecutable": "huskarl-harness",
            "CFBundleName": "HuskarlHarness", "CFBundlePackageType": "APPL",
            "CFBundleVersion": "1",
        }))
        entitlements = work / "entitlements.plist"
        entitlements.write_bytes(plistlib.dumps({
            "com.apple.application-identifier": app_id,
            "com.apple.developer.team-identifier": allowed["com.apple.developer.team-identifier"],
            "keychain-access-groups": groups,
        }))
        app = work / "HuskarlHarness.app"
        contents = app / "Contents"
        (contents / "MacOS").mkdir(parents=True)
        shutil.copy2(info, contents / "Info.plist")
        shutil.copy2(profile_path, contents / "embedded.provisionprofile")
        binary = contents / "MacOS" / "huskarl-harness"
        kind = "example" if args.cleanup else "test"
        for test in (["cleanup-test-keys"] if args.cleanup else tests):
            print(f"Building and signing {test}", flush=True)
            result = run("cargo", "rustc", "--locked", f"--{kind}", test,
                         "--message-format=json", "--", "-C",
                         f"link-arg=-Wl,-sectcreate,__TEXT,__info_plist,{info}",
                         stdout=subprocess.PIPE, text=True)
            artifacts = [json.loads(line) for line in result.stdout.splitlines()]
            for entry in artifacts:
                if entry.get("reason") == "compiler-message":
                    print(entry["message"].get("rendered", ""), file=sys.stderr, end="")
            paths = [e["executable"] for e in artifacts
                     if e.get("reason") == "compiler-artifact"
                     and e.get("target", {}).get("name") == test
                     and kind in e.get("target", {}).get("kind", [])
                     and e.get("executable")]
            if len(paths) != 1:
                raise ValueError(f"Expected exactly one executable for {test}")
            shutil.copy2(paths[0], binary)
            run("codesign", "--force", "--sign", identity, "--entitlements",
                str(entitlements), str(app))
            run("codesign", "--verify", "--strict", "--verbose=2", str(app))
            if args.cleanup:
                run(str(binary), *(["--delete"] if args.delete else []), *groups, env=test_env)
            else:
                run(str(binary), "--ignored", "--test-threads=1", "--nocapture", env=test_env)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        if error.stdout:
            print(error.stdout, file=sys.stderr)
        print(f"Command failed (exit {error.returncode}): {error.cmd}", file=sys.stderr)
        sys.exit(error.returncode)
    except (ValueError, KeyError, OSError) as error:
        print(f"Signed tests: {error}", file=sys.stderr)
        sys.exit(1)
