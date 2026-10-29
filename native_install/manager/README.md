# Manager checker and bootstrap source

The Java decision/checker sources, build helper and shell bootstrap are included.
The official APK and compiled checker JAR are external build inputs, not files
shipped by this source export. Preserve the current certificate, version, path
and artifact hash checks recorded in source and source-pins.json.

The checker queries the fixed package's current signer, canonical install path
and version. The bootstrap skips an acceptable existing official manager, permits
only its reviewed install route and refuses foreign or unsupported state. It
does not uninstall packages or copy application data, modules or grants.

Build the checker in a new active local CleanOS scratch task with
`python3 -B -m native_install.manager.build_checker --output "$TASK_SCRATCH/SukiSUManagerCheck.jar"`.
Set `ANDROID_HOME` and `JAVA_HOME` to verified existing installations. Supply the
result to the native builder through `GOOGLEBOOK_MANAGER_CHECKER`; its existing
artifact hash validation still applies. Toolchain/source changes need a reviewed
rebuild and coordinated pin updates, not bypassing the checks.

The parent must separately verify native shell/SELinux behavior, manager
recognition and user setup. Host tests do not establish an Android runtime pass.
