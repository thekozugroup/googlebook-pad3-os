# Community launch readiness

Audit date: 2026-10-29. The project is suitable for a development/research discussion. A general flashing release is not ready.

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

A 66.77-second native3 baseline showed about 5.5 GiB available RAM, 4.62% aggregate CPU load, 2.31 GiB occupied zRAM slots using about 778 MiB actual RAM, zero swap-outs and negligible memory-pressure stalls. No tuning was justified. This is a short baseline, not a heavy-load or battery benchmark.

Google's recovery catalog still lists mica R2/build 16560795, matching this port. On October 29, the maintainer acquired Google's signed mica R2-to-R5 incremental OTA, targeting CL3B.260622.276.R5/build 16693588 with the October 1 security patch. Payload hashes and RSA signatures passed; the signer matches the retained R2 donor certificate. R5 is not integrated into the Pad 3 build. Reconstruct the exact clean donor target and re-review the tablet patches before any test; never apply the laptop OTA directly to tablet firmware.

XDA's official forum rules and GPL guidance must be checked before posting or sharing binaries. Rule 15 prohibits AI-generated forum content. COMMUNITY_NOTES.md is a factual checklist for the owner to use when writing their own post; it is not a forum post.

References:

- https://xdaforums.com/t/xda-developers-forum-rules.4200559/
- https://xdaforums.com/t/mandatory-xda-developers-and-the-gpl.2645321/
- https://source.android.com/docs/core/ota/virtual_ab/implement
- https://dl.google.com/dl/edgedl/device/recovery/production_recovery.json
