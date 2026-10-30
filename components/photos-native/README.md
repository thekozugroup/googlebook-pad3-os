# Photos framework compatibility

This component puts Photos compatibility directly into the pinned GoogleBook framework. It uses no Photos module, manager app, Zygisk or Xposed API. Only the Google Photos package receives the Pixel XL Build identity and the Nexus/preload feature answers. Android version, security patch, ABI, native system properties, other apps and attestation remain unchanged.

crDroid Android17 is the behavior reference recorded in source-lock.json. The implementation is new and excludes its general PIF service, unrelated feature grants and native property virtualization. Unrelated hardware/software feature queries use the original GoogleBook implementation. The original Google Photos APK and its data are retained.

The helper has a fail-closed package guard and readback/rollback for its eight Build-field writes. A device probe must validate ART final-field writes before integration. The JAR graft must preserve all other framework methods, the five other original DEX files and the original package-manager behavior. Boot-image/cache validation and an actual boot remain separate requirements; a helper probe alone does not establish that the modified framework boots.

Any reported backup eligibility must be checked in Photos. Local identity and feature answers do not guarantee future Google server storage treatment. Compile outputs, probe JARs, signing inputs and device logs stay outside this source component.
