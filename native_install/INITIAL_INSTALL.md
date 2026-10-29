# Initial installation review

`python3 -B -m native_install.initial_install --help` describes the offline
five-image plan generator. It checks local candidate and rollback images and
emits standard fastboot commands; it does not execute them. The first installation
replaces current B through fastbootd, shrinking system_ext and product before
growing system. The kernel, rooted init_boot, hardware partitions and native
disabled-AVB configuration remain unchanged. It does not create slot A, delete
COW partitions, flash super or relock the bootloader.

Review the exact procedure, image hashes, trust inputs and explicit reset
authorization before device operations. Source export grants no device access.
Keep current rollback images, private captures and backup/waiver evidence outside
the public source tree. This document contains no local capture inventory or
claim that an existing device has satisfied the installation requirements.

Virtual A/B can retain target blocks in userdata-backed COW storage. Applying a
payload, selecting a slot or observing a ready snapshot state does not prove that
formatting userdata or metadata preserves that target. A recovery route requires
review of the exact recovery build, payload trust, snapshot-aware wipe ordering,
supported merge or cancellation behavior, target selection and completed merge
evidence. Unknown or inaccessible state requires stopping with data preserved.

A separate raw-image/fastbootd route needs a complete current allocation plan,
partition/group capacities, protected-partition preservation, firmware/boot-chain
compatibility, idle snapshot evidence and verified image hashes. Do not infer
space from alternative metadata slots or remove a COW group because it looks old.
Rollback after repartitioning or reset requires its own explicit recovery plan.

Review source/target platform signers, native UpdateEngine integration, headless
and foreground-user setup, root-manager recognition and the new updater trust
together. A host build, source test or DSU diagnostic bundle does not establish a
working or approved first installation. See PUBLIC_RELEASE.md in the repository
root for the parent's remaining source, license, artifact and hardware review.
