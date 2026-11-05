# Native updater source

Version 1.5 (code 6) retains the Window layout Quick Settings tile: Tablet layout sets
internal display 0's default to fullscreen; Desktop layout selects freeform.
Existing windows may retain their layout. Physical tablet posture remains
independent, and external displays are untouched. Add the tile through Edit.
It reuses the owner's System update SukiSU grant and verifies native boot,
current-user ownership, enforcing ksu context and the canonical system APK.
Only fixed display 0 commands run, with readback; no polling service is added.

After user unlock at boot or replacement of this updater, a bounded JobService
checks the two pinned native GMS feature profiles. NativeConfigRepair is compiled
into the built-in APK. Correct existing overrides are reused without duplicate
rows or states; unknown or conflicting state fails closed. The existing corrected
TrickyStore module and targets remain in shared userdata and are verified only;
no keybox is read or shipped. The job reuses the owner's existing root grant.
Cancellation closes the root caller pipe and stops its child; cancelled work
does not replace saved results. Configuration checks do not prove live pairing.

The installer also checks the frozen read-only BootControl getters before apply:
the current slot must be successful and active, with no snapshot merge or pending
slot switch. This check contains no BootControl setter.

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
