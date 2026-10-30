# Public publication audit

Audit date: 2026-10-30. No confirmed owner personal information, account/device
identifiers, ADB authorization or private signing keys were found in the reviewed
public source/history or the targeted published surfaces. This is a bounded
audit, not proof that every possible encoded or visual identifier is absent.

The baseline covered 279 working files and 664 Git objects, including all 412
blobs and 14 commits in the available public refs/history, author/committer and
tag metadata, filenames, remotes and reflogs. The repository was not shallow.
It also covered repository/release metadata, two release bodies, five assets'
metadata, checksums and targeted content of four large published assets totalling
about 2.89 GB. No issue/PR/comment/Actions artifacts existed at that baseline.
Known owner patterns and protected signing/ADB inputs were checked privately;
their values and raw audit reports are excluded from this repository.

Four upstream recovery PNGs contain editing timestamps and XMP document/instance
identifiers. No author, GPS or known owner pattern was found in that metadata.
Strip unnecessary editing metadata in a future reviewed recovery rebuild.
Do not silently replace historical signed release bytes or invalidate their feed.

The public component certificate is verification material, not a private key.
Generic upstream build paths and attribution in official packages are not owner
credentials; retain applicable licensing and attribution.

Binary coverage was selective. Some large inherited ramdisk files and
source-copy-only firmware partitions were outside decoded-content inspection.
There was no comprehensive OCR or visual review of every pixel. Review the
actual candidate images and source inputs again before each release.

`privacy_audit.py` checks current tracked/nonignored files, names, symlink targets,
complete reachable Git blobs/commit/tag metadata, refs and remotes. It applies
bounded credential/PII heuristics and optional external exact secret patterns,
and reports finding locations without printing matched values. Bounds or missing
history block the check. CI uses generic rules without private owner inputs.
GitHub issues/releases/assets and device images require separate review.

If a real credential is ever exposed, revoke/rotate it first and review all
surfaces and history before publishing replacements. Removing one current file
does not remove its prior commits or cached release copies. Never rewrite history
or delete shipped releases solely to silence an unexplained scanner finding.
