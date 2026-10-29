# Boot-control getter probe source

The Java probe, build helper and frozen AOSP boot AIDL sources are included.
No compiled DEX/JAR or device capture is exported. The source checks the frozen
getter transaction declarations and packages the getter probe only. Inspect the
retained AIDL license headers and review the parent native instructions.

Use an existing SDK through `ANDROID_HOME` and an existing JDK through `JAVA_HOME`.
From the checkout root, use `python3 -B -m native_install.bootcontrol.build_probe
--help` to inspect its output argument. Supply a new output in an active local
CleanOS task. Build intermediates remain under that task and are removed by the
helper. The exporter does not build, transfer or execute the probe on a device.

The parent owns any hardware execution and capture cleanup. Only the pinned
getter calls are permitted. An idle snapshot result still needs comparison with
native layout/COW evidence; the source export grants no installation approval.
