# Facts for a human-authored community introduction

These are internal preparation notes, not text for posting verbatim. XDA Rule 15 prohibits AI-generated forum content. Write the final post yourself and check the device subsection's pinned rules.

- Project: experimental GoogleBook desktop Android port for OnePlus Pad 3/erhai.
- Public source: https://github.com/thekozugroup/googlebook-pad3-os
- Published native3 download: an exact-baseline OTA for existing native2, not a fresh-install recovery ZIP.
- Confirmed maintainer run: native3 installed through the built-in updater, booted the target slot and merged while preserving userdata; SELinux stayed enforcing.
- Pen drawing/pressure was owner-confirmed with the same component; native3 service persistence and BLE reconnection were checked separately.
- Dell APKs are physically removed. The normal official SukiSU manager/root stack is 41100/UAPI 6; the shared daemon was separately migrated before the native3 reboot.
- Known native3 issue: auto-rotate resets after reboot/sign-in because the donor assumes an open laptop. A private native4 framework correction passed reboot/user startup and owner-confirmed rotation, plus both Quick Settings layout transitions. It is not a new public binary release or a stable certification.
- The owner prototype runs mica R5/native6. Diagnostics now opens and its five sections stay running, but the audit found battery, Wi-Fi/RAM calculation and missing-data display defects. Native7 has host-tested metric corrections and a fresh strict policy compile; device qualification is blocked by USB disconnection. The owner reported quota-free Photos backups. A separate code11 candidate fixes its configuration-app Binder crash. The public feed remains native3.
- External display connection was owner-confirmed. Exact resolution, audio routing and reconnect behavior still need their own test matrix.
- Keep research contributions focused on installation/recovery reproducibility, license/source documentation, device support, and finite reliability tests.
- Ask testers to remove account names, serials, MAC addresses, network details, tokens and other personal content before sharing logs. Never request passwords or private signing keys.

Consult LAUNCH_READINESS.md before inviting anyone to flash. No general-release or endorsement claim is supported.
