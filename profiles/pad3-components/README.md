# External signer input

The owner's complete DER certificate and signing profile are excluded from public
source. Supply a matching public verification certificate as a private build input
through `GOOGLEBOOK_CERTIFICATE`. Existing verification hashes remain unchanged.
No private signing key belongs in this tree. A signed APK inherently includes its
public verification certificate; that certificate is not a private signing key.
