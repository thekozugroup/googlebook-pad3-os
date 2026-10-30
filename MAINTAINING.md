# Portable maintenance workflow

The public repository is the source handoff. Work does not depend on one Mac or
one chat. Hosted Actions run source/privacy tests and daily metadata discovery.
An opt-in trusted runner validates or executes the existing offline native build
stages. Device qualification and production feed promotion remain explicit gates.
Unknown Google builds cannot safely be patched and shipped without review.
For Google-app access and certification failures, see [GOOGLE_SERVICES.md](GOOGLE_SERVICES.md).

## 1. Discover changes

`upstream-watch.yml` runs daily at 09:17 UTC and can be dispatched manually.
It reads Google's full recovery catalog, the latest public OTA index page and
the pinned LineageOS/crDroid branches in `maintenance/upstream.json`. It downloads
metadata only. The index is a discovery lead; its links are not signature proof.
Rollout-only and older index records can be missed. An unreachable or changed
source reports `incomplete`, never a false claim that no update exists.

For a local check, write the report outside the checkout:

```sh
python3 -B discover_updates.py --output "$TASK_SCRATCH/discovery.json"
```

The reviewed ARM donor is mica R5/build 16693588, October 1 security patch.
The full recovery catalog still has R2; that older entry is not a downgrade
recommendation. New URLs or source revisions require review. Verify Google's
package signatures, source/target metadata and partition hashes before use.
Do not install a laptop OTA directly on the tablet.

Set repository variable `ENABLE_UPDATE_PROPOSALS=true` to allow metadata-only
review branches/PRs. Proposals use the workflow's short-lived token and a stable
report digest; they do not change ROM pins, signing keys or the updater feed.
If GitHub disallows workflow-created PRs, the review branch remains available;
open the comparison manually. Do not broaden token or organization permissions
to work around that policy. Token-created PRs may not trigger other workflows;
dispatch source checks explicitly before merging a proposal.

## 2. Prepare a different build host

Use Python 3.11+, Git, OpenSSL and the verified tools required by the existing
builders: Android SDK/build-tools, JDK 21, Kotlin, JADX/DEX tooling, EROFS tools,
SELinux compiler and the pinned donor extractor as applicable. Provision tools
separately; no workflow installs a replacement SDK or downloads private inputs.
Hashes in component locks remain mandatory. Host executables must match the
host architecture. The recipe, nested component manifests and their receipts
must refer to that host's verified toolchain; copying old absolute paths is
insufficient. Consult BUILDING.md and each component's builder help.

Keep source under a verified local development directory. Keep inputs/signers
in protected external directories and generated outputs in owned scratch.
On macOS create a CleanOS task and verify its backup-copy exclusion. On Linux:

```sh
python3 -B maintenance_workspace.py init --project "$SOURCE_ROOT" --parent "$LOCAL_SCRATCH_PARENT"
```

The command returns a task name beneath the supplied existing physical parent.
Use that private task directory as `WORK_ROOT`; create `OUTPUT_ROOT` inside it.
Do not copy or manufacture a macOS ownership marker on Linux. Do not create a
Linux marker on macOS. Preserve source and signer backups; scratch is disposable.

Transfer required raw donor/base images, derived components, private capture
metadata and signing material through a private channel. Verify every hash on
the destination. Never attach them to an issue, PR, Actions log or public artifact.
Existing installations require the existing feed/payload/component trust keys.
A fork with new keys needs a deliberately provisioned trust configuration;
possession of the public source does not authorize signing existing devices' OTAs.

## 3. Run a reviewed job

`maintenance_job.py` calls the existing native userspace assembler or native ROM
packager. It accepts no arbitrary command, upload, reboot or flash stage. The
external job pins a clean exact source commit, reviewed donor profile, recipe,
inputs/tools and a new output location. `maintenance/job.example.json` is an
invalid template until its commit and digests are replaced with reviewed values.

File pins use `{ "path": "input:relative/file", "sha256": "..." }`.
The four roots are `input`, `tool`, `work`, `output`; absolute paths, symlink
escapes and `..` are refused. The external recipe/plan/tool/review JSON templates
use those same pins. Rebuild source-bound receipts at the exact public commit;
receipts from a different private/exported source do not qualify.

```sh
python3 -B maintenance_job.py plan --job "$JOB_FILE" --job-sha256 "$JOB_SHA256" \
  --input-root "$INPUT_ROOT" --tool-root "$TOOL_ROOT" \
  --work-root "$WORK_ROOT" --output-root "$OUTPUT_ROOT"
```

After reviewing the plan, use `execute` with `--trusted-runner` and the same
arguments. `plan_ready` verifies template pins and ownership; it explicitly does
not validate nested builder manifests or relocated provenance. Execution applies
the existing full builder validators. Use an isolated trusted source/toolchain;
Git-visible cleanliness does not detect arbitrary ignored executable state.
The assembler creates a private pinned handoff. A packaging job also
requires pins for `plan`, `tools`, `review`, `handoff`, `key`, `certificate`,
`feed_key`, `feed_public_key`, `apksigner` and `aapt2`. Its tools template uses
`"scratch": "work:."`; its review pins the exact portable plan bytes. Runtime
copies rebind paths and that plan digest only, then are removed. Keys must have
owner-only permissions. Logs and the resulting handoff stay in owned scratch.
Outputs are explicitly marked unbooted; construction does not authorize a wipe.
The package handoff authenticates the feed, checks local parts and the joined
archive hash, and binds every output filename, size and hash. Missing or extra
assets block the handoff. Recheck those bytes before any later publication.

The runner currently supports reviewed R5 sequences 5–8 and their exact Product
hashes. A later release requires reviewed source/profile changes and new tests.
Do not change the supported sequence merely to bypass a failing donor check.

For Actions, provision a dedicated self-hosted runner labelled `pad3-maintainer`,
create protected environment `native-maintenance`, and set
`ENABLE_NATIVE_RUNNER=true`. Run only trusted reviewed default-branch code.
Do not expose a signer-bearing runner to untrusted fork jobs. Configure the
runner externally with `GOOGLEBOOK_JOB_FILE`, `GOOGLEBOOK_JOB_SHA256`,
`GOOGLEBOOK_INPUT_ROOT`, `GOOGLEBOOK_TOOL_ROOT`, `GOOGLEBOOK_WORK_ROOT` and
`GOOGLEBOOK_OUTPUT_ROOT`. Then dispatch `native-maintenance.yml` in `plan` or
`execute` mode. Configure environment review rules to match the release policy.
This workflow uploads neither keys nor raw logs and performs no device action.

## 4. Qualify and promote

Run hosted source checks and the additional input/tool-dependent checks locally.
On the intended hardware verify target hashes, boot, SukiSU ABI/manager, enforcing
SELinux, snapshot state/merge, accounts, repeated rotation/layout transitions,
pen pressure/attachment, audio, Wi-Fi, Bluetooth, cameras, external display,
sleep/wake, battery/thermal behavior and all Diagnostics metrics. Inspect crash,
ANR and pressure evidence. Test the Google app and Play certification separately;
registration or root concealment is not a hardware-backed integrity verdict.
Record untested features. Never replace a failed metric with an invented value.

Before publishing, run `privacy_audit.py --repo . --history --output` to an
external path. Locally add `--secret-file` for protected owner/key patterns.
Generic CI scanning cannot recognize every owner-specific identifier. Audit
final release images, certificates, metadata, URLs, logs and GitHub surfaces
separately; consult PRIVACY_AUDIT.md. Keep raw captures private.

For a qualified update, retain one canonical signed output plus matching
sanitized evidence. Use the builder's exact release parts, checksums and signed
descriptor. Upload the immutable assets under the descriptor's release tag;
verify downloaded asset sizes/hashes and payload/feed signatures. Only then
replace `updates/erhai/stable.json` and `.sig` together in a reviewed commit.
Never edit descriptor bytes after signing, reuse an old sequence, or advertise
fingerprints that were not tested. Keep shipped archives and signing material.
The public feed remains native3 until a later candidate passes these gates.

Automatic discovery and offline execution are implemented. Automatic adaptation
of an unknown donor, unattended hardware qualification and production promotion
are not enabled. A maintainer must provision private inputs/signers and approve
new source/profile changes; moving to another host does not require this laptop.

## 5. Cleanup and handoff

Save the canonical output and necessary evidence outside disposable scratch.
Stop only owned processes and remove task-only device test installs, mounts,
containers or temporary images. On macOS finish/preview/clean the exact CleanOS
task. On Linux verify the private marker, owner and recorded task path before
removing that exact task tree; never apply a blanket cache or VM prune. Verify
cleanup and report retained outputs. Do not remove source, keys, backups, shared
SDKs or releases. No workflow performs scheduled deletion.
