# Reviewing upstream changes

Run `python3 check_updates.py --help` to inspect the available update commands.
Update checks are informational; they do not establish compatibility or install
an update. Review donor image hashes, native policy linkage, kernel compatibility,
pen upstream pins, SELinux rules, and third party licenses together.

Other agents may still be changing the private working source. Rerun the exporter
after those changes settle, review the complete allowlist and output hashes, and
verify the final candidate before creating a fresh public repository.
Never reuse the private repository's Git directory, commits, branches or remotes.
