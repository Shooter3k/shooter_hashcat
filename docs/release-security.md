# Release integrity, SBOM, and attestations

The complete Windows archive has three verification layers:

1. `SHA256SUMS` inside the archive covers every packaged source and binary
   file. Run `verify-windows-package.ps1` after extraction.
2. The archive contains an SPDX 2.3 software bill of materials (SBOM) listing
   the packaged executables and DLLs with SHA-256 checksums plus the principal
   build and runtime dependencies.
3. GitHub Actions creates signed Sigstore attestations for both build
   provenance and the SBOM. They bind the published archive digest to the tag,
   repository, workflow, and ephemeral GitHub identity that produced it.

Tagged releases always invoke `package-windows.ps1 -BuildAction Rebuild` on a
clean GitHub runner. `build-windows.ps1 -Action Build` is an incremental
developer convenience and must not be copied into a production installation or
resident-worker pool after headers, compiler flags, or shared structures have
changed. Use `-Action Rebuild` for every manually deployed production binary.

Verify the downloaded archive with GitHub CLI:

```powershell
gh attestation verify .\shooter_hashcat-<version>-windows-x64-complete.7z `
  --repo Shooter3k/shooter_hashcat
```

The release page also states the archive SHA-256. The SBOM is kept inside the
single `.7z` release asset; a workflow-side copy is used to create its signed
SBOM attestation without adding a second download asset.

Attestation proves which workflow built a particular byte-for-byte artifact.
It does not make arbitrary source or dependencies trustworthy by itself.
Review the repository, tag, workflow identity, and digest reported by the
verification command.
