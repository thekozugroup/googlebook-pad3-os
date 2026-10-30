# Reviewing upstream changes

Use [MAINTAINING.md](MAINTAINING.md) for the update workflow, runner setup,
private input handoff, qualification and release procedure. The daily hosted
workflow discovers public metadata; it never signs or installs an unknown ROM.
The reviewed job runner reuses the existing offline native builders.

The full recovery catalog currently pins mica R2. The separately reviewed
incremental OTA baseline is mica R5. A catalog match to R2 does not mean the
installed R5 base is out of date. Discovery failure is reported as incomplete.
New versions require signature verification and a reviewed source/profile change.
Existing image, method, policy, kernel and Product pins remain mandatory.

Export only reviewed source and sanitized evidence. Never copy the private
repository's Git directory, raw reports, signing material or device identifiers.
