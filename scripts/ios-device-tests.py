"""Build an automatically signed iPhone app containing the enclave mTLS tests."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent


def run(*args, **kwargs):
    return subprocess.run(args, cwd=ROOT, check=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare-only", action="store_true", help="Generate the Xcode project without signing or launching")
    parser.add_argument("--oauth-fixture", type=Path, help="Run the OAuth test with these disposable fixtures")
    args = parser.parse_args()
    test = "urlsession_oauth" if args.oauth_fixture else "urlsession_mtls"
    work = ROOT / "target" / ("ios-oauth-tests" if args.oauth_fixture else "ios-device-tests")
    work.mkdir(parents=True, exist_ok=True)
    team = os.environ.get("HUSKARL_IOS_TEAM")
    if not team and os.environ.get("HUSKARL_PROVISIONING_PROFILE"):
        profile = run("security", "cms", "-D", "-i", os.environ["HUSKARL_PROVISIONING_PROFILE"],
                      stdout=subprocess.PIPE).stdout
        team = plistlib.loads(profile)["Entitlements"]["com.apple.developer.team-identifier"]
    if not team:
        raise ValueError("Set HUSKARL_IOS_TEAM to your Apple development team identifier")
    bundle = os.environ.get("HUSKARL_IOS_BUNDLE_ID", f"io.huskarl.enclave-tests.{team.lower()}")
    if args.oauth_fixture:
        bundle += ".oauth"
        fixture = work / "oauth-fixture"
        fixture.mkdir(exist_ok=True)
        for name in ["root.der", "issuer.der", "issuer.key", "metadata.json", "resource-url.txt"]:
            shutil.copy2(args.oauth_fixture / name, fixture / name)
    link_args = []
    if args.oauth_fixture:
        # Cargo does not track changes to objects supplied via link-arg.
        version = hashlib.sha256((ROOT / "support/ios_test_app.m").read_bytes()).hexdigest()[:16]
        wrapper = work / f"ios_test_app_{version}.o"
        run("xcrun", "--sdk", "iphoneos", "clang", "-target", "arm64-apple-ios18.0",
            "-fobjc-arc", "-c", "support/ios_test_app.m", "-o", str(wrapper))
        link_args = ["--", "-C", f"link-arg={wrapper}",
                     "-C", "link-arg=-framework", "-C", "link-arg=UIKit",
                     "-C", "link-arg=-Wl,-e,_huskarl_test_app_main"]
    build = subprocess.run(
        ["cargo", "rustc", "--locked", "--features", "urlsession", "--target",
         "aarch64-apple-ios", "--test", test, "--message-format=json", *link_args],
        cwd=ROOT, env=dict(os.environ, IPHONEOS_DEPLOYMENT_TARGET="18.0"),
        stdout=subprocess.PIPE, text=True, check=False)
    artifacts = [json.loads(line) for line in build.stdout.splitlines()]
    for artifact in artifacts:
        if artifact.get("reason") == "compiler-message":
            print(artifact["message"].get("rendered", ""), end="")
    build.check_returncode()
    binaries = [a["executable"] for a in artifacts if a.get("executable")
                and a.get("target", {}).get("name") == test]
    if len(binaries) != 1:
        raise ValueError("Expected one iOS test executable")
    shutil.copy2(binaries[0], work / "huskarl-tests")
    (work / "Info.plist").write_bytes(plistlib.dumps({
        "CFBundleIdentifier": "$(PRODUCT_BUNDLE_IDENTIFIER)",
        "CFBundleExecutable": "$(EXECUTABLE_NAME)", "CFBundleName": "HuskarlTests",
        "CFBundlePackageType": "APPL", "CFBundleVersion": "1",
        "CFBundleShortVersionString": "1.0", "LSRequiresIPhoneOS": True,
        "UILaunchScreen": {},
        "UIApplicationSceneManifest": {
            "UIApplicationSupportsMultipleScenes": False,
            "UISceneConfigurations": {
                "UIWindowSceneSessionRoleApplication": [{
                    "UISceneConfigurationName": "Huskarl Tests",
                    "UISceneDelegateClassName": "HuskarlTestSceneDelegate",
                }],
            },
        } if args.oauth_fixture else {},
        "NSLocalNetworkUsageDescription": "Connect to the temporary OAuth and protected-resource test servers on your Mac.",
        "UISupportedInterfaceOrientations": ["UIInterfaceOrientationPortrait",
                                             "UIInterfaceOrientationPortraitUpsideDown",
                                             "UIInterfaceOrientationLandscapeLeft",
                                             "UIInterfaceOrientationLandscapeRight"],
    }))
    (work / "Tests.entitlements").write_bytes(plistlib.dumps({
        "keychain-access-groups": ["$(AppIdentifierPrefix)$(PRODUCT_BUNDLE_IDENTIFIER)"],
    }))
    settings = {
        "PRODUCT_NAME": "HuskarlTests", "PRODUCT_BUNDLE_IDENTIFIER": bundle,
        "DEVELOPMENT_TEAM": team, "CODE_SIGN_STYLE": "Automatic",
        "CODE_SIGN_ENTITLEMENTS": "Tests.entitlements", "INFOPLIST_FILE": "Info.plist",
        "SDKROOT": "iphoneos", "SUPPORTED_PLATFORMS": "iphoneos",
        "IPHONEOS_DEPLOYMENT_TARGET": "18.0", "TARGETED_DEVICE_FAMILY": "1,2",
        "ENABLE_USER_SCRIPT_SANDBOXING": "NO",
        "ALWAYS_SEARCH_USER_PATHS": "NO",
    }
    # Xcode supplies the development profile and signs the prebuilt Rust test
    # executable. Keep all generated project and signing products under target/.
    objects = {
        "A00000000000000000000001": {
            "isa": "PBXProject", "mainGroup": "A00000000000000000000002",
            "buildConfigurationList": "A00000000000000000000003",
            "compatibilityVersion": "Xcode 14.0", "projectDirPath": "",
            "targets": ["A00000000000000000000005"],
        },
        "A00000000000000000000002": {"isa": "PBXGroup", "children": ["A00000000000000000000006"], "sourceTree": "<group>"},
        "A00000000000000000000003": {"isa": "XCConfigurationList", "buildConfigurations": ["A00000000000000000000004"], "defaultConfigurationName": "Debug"},
        "A00000000000000000000004": {"isa": "XCBuildConfiguration", "name": "Debug", "buildSettings": {}},
        "A00000000000000000000005": {
            "isa": "PBXNativeTarget", "name": "HuskarlTests", "productName": "HuskarlTests",
            "productType": "com.apple.product-type.application",
            "productReference": "A00000000000000000000006",
            "buildConfigurationList": "A00000000000000000000007",
            "buildPhases": ["A00000000000000000000009"], "dependencies": [], "buildRules": [],
        },
        "A00000000000000000000006": {"isa": "PBXFileReference", "explicitFileType": "wrapper.application", "path": "HuskarlTests.app", "sourceTree": "BUILT_PRODUCTS_DIR"},
        "A00000000000000000000007": {"isa": "XCConfigurationList", "buildConfigurations": ["A00000000000000000000008"], "defaultConfigurationName": "Debug"},
        "A00000000000000000000008": {"isa": "XCBuildConfiguration", "name": "Debug", "buildSettings": settings},
        "A00000000000000000000009": {
            "isa": "PBXShellScriptBuildPhase", "buildActionMask": 2147483647,
            "files": [], "inputPaths": ["$(SRCROOT)/huskarl-tests"],
            "outputPaths": ["$(TARGET_BUILD_DIR)/$(EXECUTABLE_PATH)"],
            "shellPath": "/bin/sh", "runOnlyForDeploymentPostprocessing": 0,
            "shellScript": 'set -eu\nmkdir -p "$TARGET_BUILD_DIR/$WRAPPER_NAME"\ncp "$SRCROOT/huskarl-tests" "$TARGET_BUILD_DIR/$EXECUTABLE_PATH"\n',
        },
    }
    if args.oauth_fixture:
        objects["A00000000000000000000009"]["shellScript"] += (
            'cp -R "$SRCROOT/oauth-fixture" "$TARGET_BUILD_DIR/$WRAPPER_NAME/"\n')
    project = work / "HuskarlTests.xcodeproj"
    project.mkdir(exist_ok=True)
    (project / "project.pbxproj").write_bytes(plistlib.dumps({
        "archiveVersion": "1", "objectVersion": "56", "classes": {},
        "objects": objects, "rootObject": "A00000000000000000000001",
    }))
    print(f"Prepared {project}", flush=True)
    if args.prepare_only:
        return
    run("xcrun", "devicectl", "list", "devices", "--json-output", str(work / "devices.json"))
    devices = json.loads((work / "devices.json").read_text())["result"]["devices"]
    requested = os.environ.get("HUSKARL_IOS_DEVICE")
    devices = [d for d in devices if d["hardwareProperties"].get("reality") == "physical"
               and d["connectionProperties"].get("pairingState") == "paired"
               and (not requested or requested in [d["identifier"], d["hardwareProperties"]["udid"]])]
    if len(devices) != 1:
        raise ValueError("Connect one iPhone, or select it with HUSKARL_IOS_DEVICE")
    device = devices[0]
    if device["deviceProperties"].get("developerModeStatus") != "enabled":
        raise ValueError("Enable Developer Mode on the iPhone, restart, and confirm before running tests")
    udid = device["hardwareProperties"]["udid"]
    run("xcodebuild", "-quiet", "-project", str(project), "-scheme", "HuskarlTests",
        "-destination", f"id={udid}", "-derivedDataPath", str(work / "build"),
        "-allowProvisioningUpdates", "-allowProvisioningDeviceRegistration", "build")
    app = work / "build" / "Build" / "Products" / "Debug-iphoneos" / "HuskarlTests.app"
    run("xcrun", "devicectl", "device", "install", "app", "--device", udid, str(app))
    try:
        result = subprocess.run(
            ["xcrun", "devicectl", "device", "process", "launch", "--device", udid,
             "--console", "--terminate-existing", bundle,
             "--ignored", "--test-threads=1", "--nocapture"],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False)
    finally:
        if args.oauth_fixture:
            run("xcrun", "devicectl", "device", "uninstall", "app", "--device", udid, bundle)
    print(result.stdout)
    result.check_returncode()
    expected = 1 if args.oauth_fixture else 2
    if f"test result: ok. {expected} passed; 0 failed" not in result.stdout:
        raise ValueError(f"The iPhone did not report all {test} tests passing")


if __name__ == "__main__":
    try:
        main()
    except (subprocess.CalledProcessError, ValueError, OSError) as error:
        print(f"iPhone tests: {error}", file=sys.stderr)
        sys.exit(1)
