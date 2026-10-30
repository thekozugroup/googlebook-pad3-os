#!/usr/bin/env python3
"""Check source contracts; device hooks and Google server quota need separate evidence."""
import argparse
from pathlib import Path
import re

PACKAGE = 'com.google.android.apps.photos'
JAVA = Path('app/src/main/java/io/github/samson910022/pixelifyphotos')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify_source(source):
    def read(name):
        return (source / JAVA / (name + '.kt')).read_text()
    scope, constants = read('ScopePolicy'), read('Constants')
    body = re.search(r'fun shouldSpoof\(packageName: String\?\): Boolean\s*\{([^}]*)\}', scope)
    require(body is not None and body[1].strip() == 'return packageName == Constants.PACKAGE_NAME_GOOGLE_PHOTOS', 'Exact Photos eligibility gate required')
    require(f'const val PACKAGE_NAME_GOOGLE_PHOTOS = "{PACKAGE}"' in constants, 'Photos package constant changed')
    module, device, feature = read('PixelifyModule'), read('DeviceSpoofer'), read('FeatureSpoofer')
    require(module.count('if (!ScopePolicy.shouldSpoof(params.packageName))') == 2, 'Both lifecycle callbacks need the shared gate')
    for loader in ['defaultClassLoader', 'classLoader']:
        require(f'FeatureSpoofer.hook(this, params.{loader}, params.packageName)' in module, 'Feature hook must receive package identity')
    gate = 'if (!ScopePolicy.shouldSpoof(packageName)) return'
    for text in [device, feature]:
        require(gate in text and text.index(gate) < text.index('module.hook('), 'Spoof entry must fail closed before hooks')
    require(device.index(gate) < device.index('ensureNativeLoaded(module)'), 'Guard native/Build path')
    fields = re.search(r'VERSION_FIELD_NAMES = setOf\(([^)]*)\)', device)
    require(fields is not None and set(re.findall(r'"([A-Z_]+)"', fields[1])) == {'INCREMENTAL', 'SECURITY_PATCH', 'RELEASE', 'SDK', 'SDK_INT'}, 'Real version/security fields must be excluded')
    for fragment in ['val profileProps = deviceEntries.props.filterKeys { it !in VERSION_FIELD_NAMES }', 'profileProps.forEach', 'hookSystemProperties(module, profileProps, verboseLog)', 'verifySpoof(profileProps, verboseLog)']:
        require(fragment in device, 'Build, property and readback paths must use filtered profile')
    for forbidden in ['PREF_SPOOF_ANDROID_VERSION_', 'setStaticField(Build.VERSION::class.java', 'putKey("ro.build.version.']:
        require(forbidden not in device, 'Real OS/API/security version override is forbidden')
    metadata = source / 'app/src/main/resources/META-INF/xposed'
    props = dict(line.split('=', 1) for line in (metadata / 'module.prop').read_text().splitlines() if '=' in line)
    require(props == {'minApiVersion': '101', 'targetApiVersion': '101', 'staticScope': 'true'}, 'Modern libxposed API101/static scope required')
    require((metadata / 'scope.list').read_text().strip() == PACKAGE, 'Only Photos may be scoped')
    require('val defaultDeviceName = "Pixel XL"' in read('DeviceProps'), 'Default profile must remain Pixel XL')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    args = parser.parse_args()
    verify_source(args.source)
    print('PASS: exact Photos scope, API101, default profile and real-version preservation contracts')
