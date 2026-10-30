# Local build inputs

Use an existing local SDK and JDK; do not copy full toolchains into this checkout.
On macOS, create a CleanOS task for disposable build output and verify its
backup-copy exclusion. On Linux, use maintenance_workspace.py to create an
explicitly owned private task. See MAINTAINING.md for both host paths.
Pass that task's resolved scratch path to builders that require it.
Install prerequisites separately; this source export downloads and installs nothing.

The portable toolchain lock retains exact dependency hashes. It refers to
`build-inputs/kotlin`, `build-inputs/android-sdk` and `build-inputs/jdk-21`.
Configure these private, ignored locations to use verified existing dependencies.
The donor lock refers to `build-inputs/donor-images/system_a.img`; preserve all
pinned input hashes and acquire firmware separately under its applicable terms.
`GOOGLEBOOK_INPUTS` can select another local image input root for the pen builder.

Diagnostic image builds require an explicit external ADB public authorization
file through `GOOGLEBOOK_ADB_PUBLIC_KEY`. This is host authorization material;
keep generated diagnostic images private. Public release images need a separate
review that removes host authorization and owner data. Do not publish an existing
diagnostic ZIP just because its source passes this exporter.

The pen layer builder requires an external public certificate via
`GOOGLEBOOK_CERTIFICATE`, defaulting to `build-inputs/component-certificate.der`.
Its certificate, APK and base-image verification pins remain unchanged. Replacing
the signer requires a coordinated reviewed build, new legitimate input pins and
matching SELinux mappings. No placeholder is accepted as a functioning signer.
Signing private keys remain external. The owner DER file is deliberately omitted.

The builders preserve their existing safeguards and experimental status. Consult
their CLI help, inspect the inputs, and review each generated result before use.

The build2-to-native3 UAPI 5-to-6 transition requires a separate one-time install
of the pinned official 41100 daemon after OTA apply and before the first reboot.
The updater did not perform that migration. Read the prerequisites, exact order
and qualified runtime record in [PUBLIC_RELEASE.md](PUBLIC_RELEASE.md#native3-runtime-record-and-one-time-root-migration).
The manager's boot-time self-upgrade does not migrate the shared daemon or
establish automatic compatibility with future SukiSU versions.
