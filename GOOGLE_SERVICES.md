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
