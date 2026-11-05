# Community launch readiness

Audit date: 2026-10-30. The project is suitable for a development/research discussion. A general flashing release is not ready.

The published native3 OTA updates only its exact existing native2 fingerprint and slot. It is not a first-install package for stock OxygenOS or an arbitrary crDroid build. The maintainer's successful native update and snapshot merge are documented in PUBLIC_RELEASE.md.

Before inviting new owners to install:

1. Publish and test an exact public first-install path, with model/base/partition prerequisites and compatible recovery.
2. Test a snapshot-aware recovery and restore procedure. Slot switching after merge is not a guaranteed rollback, and it does not restore shared root data.
3. Resolve donor redistribution, applicable notices and a license for original project source. Availability of donor downloads does not establish redistribution rights.
4. Provide complete device-specific kernel/module source links, revisions, build information and the precise module correction. Source review and privacy checks do not replace license obligations.
5. Provide a sanitized native input manifest and complete independent build/verification instructions. Contributor builds must use their own trust configuration; maintainer private keys stay private.
6. Publish a versioned hardware/reliability matrix. Native3 has a confirmed reboot/sign-in rotation regression. The private native4 correction passed reboot, personal-user startup, and owner rotation confirmation; the layout tile switched both ways. This does not qualify other hardware or a fresh-install route. Do not transfer all native2 observations to a later build automatically.
7. Keep native2-to3's separate shared-daemon migration prominent. A normal manager APK upgrade is not a kernel/module/daemon migration.

The public source has hash-bound patches and fail-closed image/signature/source checks. Those are useful safeguards; they do not establish stable everyday operation or a safe first install on another tablet.

Native8's Google-app access blocker was resolved on the maintainer tablet after
official custom-ROM registration and a targeted refresh of stale generated
compliance caches. Google services then returned a non-provisional allow result;
the Google app and Play Store reopened normally after process restarts. Drive,
Docs, Sheets and Slides reached their expected Google web interfaces through
Chrome. Play Store still reports that the device is not certified, and its own
diagnostic requires a locked bootloader. No Play Integrity pass is established.
Do not relock this custom system to try to obtain certification. App access is
distinct from manufacturer certification; see GOOGLE_SERVICES.md. General
release and security-sensitive app compatibility remain unqualified.
See MAINTAINING.md for the portable workflow and PRIVACY_AUDIT.md for audit scope.

Full native phone integration is still a release blocker. The unsupported AVF
attestation-provider hang has a source correction and passed reboot checks.
The maintainer's existing rooted compatibility setup now establishes the secure
companion channel and passes the native phone-app chooser, AV1 AppCast video,
remote `7+5=12` and cold-launch `5+6=11`, without an explicit diagnostic service
start. Native Ambient four-flag anonymous source-0 publication, real client commit,
cold restart and overnight persistence passed. The deployed two-flag
receiver-settings profile exposes the native Notifications switch; off/on passed
and the original on state was restored. Tablet role 2 and phone-only source
controls are preserved. Text/PNG file roundtrips and thumbnail checks passed;
test files and temporary phone-file probes were removed.

Native Chrome task handoff also passed end to end: the phone advertised the task,
a native badged taskbar click produced a correlated request/result and local
Chrome launch, and the local URL matched the exact test page including its
fragment. This qualifies the tested Chrome URL restoration. Handoff requires
opt-in apps; arbitrary apps remain unqualified. Both test tabs were removed and
the original phone tab preserved. Fresh server sync, reboot persistence and general file/media sync
remain unqualified. Qualcomm provisioning remains unrepaired;
rooted-module compatibility does not establish genuine factory trust or Strong
Integrity. The module correction and native config helper have source recipes;
no distributed OTA containing them is claimed. See GOOGLE_SERVICES.md and
qa/PHONE_INTEGRATION.md for the measured scope. These checks do not establish a
general stable release.

Private native9 includes the AVF correction and a layout-tile race fix. Its
owner update preserved all 347 existing package UIDs and both accounts, matched
all 15 live partition hashes, and completed snapshot merging on successful slot
A. The actual Quick Settings tile passed 20 rapid-tap, panel-collapse/reopen and
repeated-tap trials. These finite checks do not qualify full phone integration
or repeat every prior hardware test. The public binary feed remains native3.

A 66.77-second native3 baseline showed about 5.5 GiB available RAM, 4.62% aggregate CPU load, 2.31 GiB occupied zRAM slots using about 778 MiB actual RAM, zero swap-outs and negligible memory-pressure stalls. No tuning was justified. This is a short baseline, not a heavy-load or battery benchmark.

Google's recovery catalog lists mica R2/build 16560795. On October 29 the maintainer acquired and verified the signed R2-to-R5 ARM incremental OTA targeting CL3B.260622.276.R5/build 16693588 with the October 1 patch. Native5 preserved accounts/apps and completed a 15-minute probe with one Diagnostics crash. Native6 addresses the missing laptop vendor service; it installed, booted and matched all 15 live image hashes, with root and SELinux enforcing. Native6 passed five-section Diagnostics startup checks; its finite probe had no new crashes but one ADB-unavailable sample. Native8 combines remaining metric corrections with Photos-only framework compatibility. It installed without a reset, booted, matched all 15 live targets, and passed installed framework scope probes. Photos and all five Diagnostics sections passed owner-device checks, the old Photos module is removed, and a three-minute probe captured no errors or new crashes. Diagnostics still needs its scoped adapter; factory hardware routines remain limited. See PUBLIC_RELEASE.md for coverage and limitations. No stable or new public binary release is claimed; the public feed stays native3. Never apply the laptop OTA directly to tablet firmware.

XDA's official forum rules and GPL guidance must be checked before posting or sharing binaries. Rule 15 prohibits AI-generated forum content. COMMUNITY_NOTES.md is a factual checklist for the owner to use when writing their own post; it is not a forum post.

References:

- https://xdaforums.com/t/xda-developers-forum-rules.4200559/
- https://xdaforums.com/t/mandatory-xda-developers-and-the-gpl.2645321/
- https://source.android.com/docs/core/ota/virtual_ab/implement
- https://dl.google.com/dl/edgedl/device/recovery/production_recovery.json
