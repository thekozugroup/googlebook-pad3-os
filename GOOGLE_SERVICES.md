# Google-app access and device certification

These are separate checks. Google's custom-ROM registration can permit Google
apps to run; it does not turn this rooted port into an approved manufacturer
build. The maintainer tablet currently opens Google apps, while Play Store's
About page still reports that the device is not certified. Its official repair
check explicitly requires a locked bootloader. Never relock this port to silence
that message: the installed custom system is not the stock manufacturer image.

## Registered device still shows a blocking warning

The native8 incident was tested with Google Play services 26.43.30. Registration
succeeded, but signed response caches retained the earlier denial. Restarting
processes alone did not invalidate those disk caches.

1. Register the active Android profile's GSF Android ID privately on
   [Google's official registration page](https://www.google.com/android/uncertified/).
   Use its documented current-user retrieval method. A headless system user and
   the signed-in user can have different IDs. Match the actual service/profile;
   do not assume every profile needs registration. Keep IDs out of Git, logs,
   screenshots intended for publication and public support reports.
2. Allow Google's response to update and inspect the actual serving GMS instance.
   Its compliance dump can show `shouldAllowGmsFunctionality`, `isProvisional`
   and Gservices status fields. Do not infer undocumented numeric status meanings.
   The successful incident had an explicit non-provisional allow response.
3. If that response allows access but a particular app still blocks, inspect its
   generated `cache/gmscompliance.pb`. Back it up privately and refresh only the
   verified stale cache after preserving unsaved work. The incident affected the
   Google app, Play Store, Drive, Docs, Sheets, Slides and Maps. Each regenerated
   cache must come from the normal Google service path. Do not write a canned
   allow result, clear account databases or disable the compliance UI.
4. The GMS signed-response store is separate. In the inspected version it uses
   `files/gmscompliance/shared/cache.pb` or an alternate multiprocess filename.
   An earlier targeted refresh of that generated store preceded the allow result.
   Preserve a private backup, verify the installed version/store role, and retain
   backoff/rate-limit state. Do not turn this into a periodic deletion service.
   New GMS versions need fresh review; neither cache absence nor a check-in
   broadcast proves that Google granted access.
5. Reopen the affected apps with the screen unlocked and verify their actual UI.
   Repeat a process restart. A locked SystemUI screen is not a successful app
   test. On GoogleBook, workspace launchers may open Chrome web interfaces;
   verify the expected product/route. An old registration browser tab displaying
   warning text is also not proof that Chrome itself is blocked.

Account data and application settings were retained. No new root or attestation
module was needed for this access repair. The existing installed OS was retained;
this was not an OTA or a new ROM build.

## Native phone integration

Continue activity, phone app casting and notification/file sync need separate
runtime qualification. A working QR screen or enabled feature flag does not
establish a secure phone connection.

The owner confirmed that mirrored phone notifications arrive and their actions
work. Before the compatibility repair below, opening one launched a blank AppCast window. These paths
must be tracked separately: in the inspected Ambient version, notification
actions can use the client host while activity clicks require an AppCast device.
The activity renders empty Compose content until that matching device is
available; it has no initial missing-device error UI. The earlier window had
an idle main thread and no video surface or decoder. Companion transport logs
showed attested-key generation failing through RKPD before streaming. The
subsequent AppCast checks below passed. Notification success alone does not
establish an AppCast pass.

The maintainer tablet displays the phone's Calculator through AppCast with AV1
video and returns `12` after tablet touch input enters `7+5`. Its native phone-app
chooser lists the phone's applications and launches Calculator. A cold app launch
also passed remote `5+6=11`. The companion transport reports an established secure
connection. These checks passed without an explicit diagnostic service start,
tablet reboot or phone USB access, preserving accounts and data.

This test uses the owner's existing TrickyStore OSS compatibility setup, with
an additional correction for system callers. Android reserves the exact
attestation application ID `AndroidSystem`, version 1 and no signature digests,
for UIDs 0 and 1000. The inspected module incorrectly enumerated their ordinary
shared-UID packages. Its generated system certificate had a 733-byte application
ID; the correction produces the required 26-byte value. The standard Android
peer verifier accepts the corrected test chain (result 0) and rejects a changed
challenge (result 8). The verifier, challenge checks and keybox were not changed.
This is rooted-module compatibility; it does not establish genuine factory trust,
Strong Integrity or a repair of Qualcomm provisioning. The
[pinned offline recipe](components/trickystore-system-identity/README.md)
reproduces the installed patch byte for byte and rejects other module versions.

The native Ambient consumer also required four existing non-authentication
feature overrides. Native source-0 publication for the anonymous account passed,
followed by a genuine client commit, cold app restart and overnight persistence.
A fresh server sync remains unqualified. Private native10 was installed through
the built-in A/B updater without a reset and passed two complete OS reboots.
The embedded startup check succeeded automatically after both boots, before
opening System update, and read-only inspection confirmed all six native
source-0 state links. Root, SELinux enforcing, accounts and installed apps were
preserved. Native AppCast video/input and finite phone-file roundtrips also
passed after the update. This qualifies the current pinned versions on the
maintainer tablet; it does not qualify future GMS or module updates. The
[native config helper](components/phone-feature-config/README.md) also deployed
the receiver-settings flags `45742359` and `45784133`. Continue activity now shows
the native enabled Notifications switch; an actual off/on test passed and restored
its original on state. Tablet role 2 is preserved; source-only controls remain on
the phone.

The receiver's Android 17 local-network permission is already granted, and its
`com.google.desktop.gms` feature is present. A read-only comparison against the
maintainer-extracted Pad 3 `.600` vendor archive found eight inspected KeyMint
service/library/configuration files identical to the installed base. Four
inspected security-firmware images also match that archive in both slots. This
does not establish an OEM signature check, complete firmware equivalence or a
provisioning repair. No replacement HAL or firmware was installed.

The port disables the laptop's Trusty security VM while retaining Qualcomm's
native security services. It must also set `avf.remote_attestation.enabled=0`
at boot. Otherwise RKPD enumerates the unsupported AVF provider and blocks in
its missing Trusty accessor; repeated attempts exhaust its Binder threads.
Android 17 documents this property as the supported way to disable VM remote
attestation without disabling ordinary virtualization. The shared image planner
now includes it. [AOSP configuration](https://android.googlesource.com/platform/packages/modules/Virtualization/+/refs/heads/android17-release/docs/vm_remote_attestation.md)

On the maintainer tablet, this correction removed the AVF hang and survived two
reboots through a temporary root configuration. Private native9 now includes it
in the image and booted with the temporary module absent. Continue activity became
visible after separately correcting its scoped configuration. The native Qualcomm CSR
path still failed, including a clean boot with TrickyStore disabled. Basic TEE
key generation and signing passed; a temporary app's factory-attestation fallback
failed with `SECURE_HW_COMMUNICATION_FAILED`. Its key and app were removed, and
the original provisioning policy and TrickyStore state were restored.

An isolated DSU comparison of the saved pre-port crDroid system reproduced the
same standard `cmd remote_provisioning csr default` failure and Qualcomm TA
error `-18` on fresh test data, without the root modules loaded. It shared the
current kernel and vendor firmware; it was not a stock-firmware qualification.
The diagnostic image added only private ADB setup files. Googlebook was restored
afterward, and the test DSU, uploads and decompressed candidates were removed.

The standard command uses an empty key list. A separate native test generated a
fresh HAL key and requested a CSR with that key and a random 32-byte challenge;
the CSR still failed. No key alias was installed, and no key or CSR was exported.
The QTI error's internal meaning remains unconfirmed; it is not evidence that
the tablet's provisioning material is damaged.

Native9's matching vendor-library analysis and a fresh runtime capture narrow
the boundary further: `IKMHal_sendCmd failed with rsp_header->status: -18`
precedes the CSRv2 failure. The transport returned a response containing that
status. Its internal cause is still unknown; do not translate it to an AOSP
error name without evidence. The installed Ambient application's service factory
still selects Android Keystore challenge attestation. Its
`DeviceLink.useConnectionHandshake` flag is read only for diagnostics in this
APK; changing it does not select an alternative authentication path.

Read-only prefix hashes of `keymaster`, `tz`, `spuservice` and `uefisecapp`
match between both slots and the retained October 17 crDroid payload metadata.
The latest firmware-list change preceding that release names
`OPD2415_16.0.10.600(EX01)`, as do the reviewed current device trees. This is
useful provenance evidence, not proof of complete OEM compatibility or a known
firmware repair for CSRv2. No firmware was changed.
[crDroid firmware source before October 17](https://github.com/crdroidandroid/android_device_oneplus_erhai/blob/24633e3fbf51c4b425589b6fd356d436e9dfc527/proprietary-firmware.txt)

The installed framework's standard peer-device verifier also requires a
hardware-backed certificate reporting verified, locked boot. The actual
bootloader state is unlocked. The alternative TrustToken path still requests
an Android Keystore attested batch key. Correcting eligibility switches or
property displays alone does not satisfy these security requirements.
[AOSP peer-profile checks](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/android17-release/services/core/java/com/android/server/security/AttestationVerificationPeerDeviceVerifier.java)

Paired-phone file QA passed exact roundtrips for an 89-byte text file and a
98-byte synthetic PNG. Its 32×32 thumbnail center pixel was `0xff008cdc`. All test
files were deleted and temporary phone-file probes removed. These finite checks
do not qualify general file/media sync; see [file QA](qa/PHONE_INTEGRATION.md).

Native Chrome task handoff passed end to end for an isolated public test URL.
The phone advertised Chrome on the existing association; clicking its native
badged taskbar item produced a correlated handoff request, phone result and
successful tablet-local Chrome activity launch. Local Chrome displayed the actual
page, and its URL bar matched the exact expected URL including the test fragment.
This verifies Chrome URL restoration without phone USB, a fixture APK, new flags
or a direct local URL launch. Handoff requires opt-in apps; arbitrary apps and
broader app-state restoration remain unqualified. Both test tabs were closed;
the original phone tab and tab count were preserved.

Fresh server sync, reboot persistence and remaining settings paths remain
unqualified. The module correction and native config helper have source recipes;
no distributed OTA containing them is claimed.
Preserve account and Keystore data; do not reset, relock or disable peer
verification to claim full qualification.

## Certification and integrity limits

Check Play Store → Settings → About → Play Protect certification separately.
Google's official device repair can identify the unlocked bootloader even after
the app-access exemption is working. A property change or an app opening without
a warning is not evidence of manufacturer certification.

Google documents hardware-backed locked-bootloader and certified-manufacturer
image requirements for Android 13+ `MEETS_DEVICE_INTEGRITY`. Registration does not
establish that verdict. No Device/Strong Integrity pass or payment/banking-app
compatibility is claimed. A stock certification route would replace the port
and root setup; it needs its own verified manufacturer firmware and recovery
procedure before any lock or erase action.

Primary references:

- [Google's custom-ROM registration guidance](https://www.google.com/android/uncertified/warningauto)
- [Google's certification checks and repair results](https://support.google.com/android/answer/7165974?hl=en-GB)
- [Play Integrity verdict requirements](https://developer.android.com/google/play/integrity/verdicts)
