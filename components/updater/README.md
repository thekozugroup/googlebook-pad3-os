# Native updater source

The source, compile-only Android API declarations, host tests, manifest, donor API
pins and integration requirements are included. No APK or release key is copied.
The feed targets the parent's public repository and `refs/heads/main/updates/erhai/stable.json`.
`feed-empty.json` is a local empty fixture, not a published or signed update feed.

Run `python3 build_updater.py --help` from the checkout root. The portable toolchain
lock refers to ignored `build-inputs/android-sdk` and `build-inputs/jdk-21` paths;
reuse verified existing installations and preserve every hash. `GOOGLEBOOK_INPUTS`
selects the private donor-image input root, defaulting to `build-inputs`.
Use an active CleanOS scratch directory. A verification key is an explicit external
public SPKI DER input; omission keeps update verification unprovisioned and closed.
Signing private keys and owner certificate files stay external.

The exported builder creates its own fresh build report instead of reading private
integration evidence. Native UpdateEngine integration, enforcing policy, platform
signer grants, active/full-user installation and Settings behavior need the parent's
review and hardware validation. Source/host tests do not establish successful OTA.
