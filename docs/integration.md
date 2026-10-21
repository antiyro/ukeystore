# Integration

The patch targets AOSP `platform/system/security` at the public commit in
[aosp-base.json](../aosp-base.json). Start with a clean checkout of that revision
inside a matching AOSP build tree. The helper checks the commit and all five
preimage hashes before writing anything. It does not download dependencies,
build images or contact a device.

```sh
python3 tools/integrate.py --system-security /path/to/aosp/system/security
python3 tools/integrate.py --system-security /path/to/aosp/system/security --apply
```

This adds `src/attestation_shim.rs`, the C++ implementation and two configuration
files to keystore2, then patches its Rust hook sites and Soong dependencies.
Build the `keystore2` target using the normal AOSP build environment. Package the
result through your ROM's existing build process. No prebuilt binary is included.

The Rust dependencies include Binder, `IPackageManagerNative`, KeyMint AIDL,
`anyhow` and `lazy_static`. The C++ code links the platform's `libcrypto`.
This repository does not provide a complete AOSP/toolchain manifest. A successful
host test does not establish that a given vendor ROM can build or run the service.

## Configuration

The installed paths are:

| File | Purpose |
| --- | --- |
| `/system/etc/security/ukeystore-attest-targets.conf` | Mode and caller selection |
| `/system/etc/security/ukeystore-profile.json` | Attestation metadata |
| `/data/misc/keystore/ukeystore-keybox.xml` | Externally provisioned keybox, preferred when present |
| `/system/etc/security/ukeystore-keybox.xml` | Optional fallback keybox path |

The repository provides no keybox. No build rule installs one.

`mode=skeleton` leaves callers unselected. `mode=real` enables configured
selection. Exact UIDs and inclusive ranges are checked before package lookup.
Ranges select every caller in the interval; shared UIDs can include multiple
packages. UID assignments depend on the installation and Android user.

The target file is loaded once at the first hook call. Successful package
lookups are cached for the lifetime of the service; transient Binder failures
are retried. Profile and keybox files are read on each chain-building attempt.
The profile is a flat JSON object; the current minimal parser does not support
escaped strings or nested values and defaults absent fields to empty/zero values.
The XML loader is also a minimal parser, not a general XML validator.

The supplied profile contains placeholders, not a usable device identity. Patch
levels and root-of-trust fields are declared certificate data. They do not
measure installed security patches or change the hardware boot state.

## Runtime behavior

- The `generateKey` hook requires an existing KeyMint certificate leaf. It retains
  that leaf's public key, the request challenge and the application ID added by
  keystore2. It constructs other certificate fields from configured and fixed
  values. The Rust path currently assumes EC P-256 sign/verify descriptors.
- Selected callers skip the remote-provisioned attestation-key path and attempt
  the factory-key path. This happens before chain replacement; a missing keybox
  does not undo that RKP selection change. Devices without a usable factory-key
  fallback may fail. This is not a software KeyMint replacement.
- If chain building returns an error, the generation hook retains the chain it
  received. Error cases can still affect logs and the attestation-key selection.
- The `getKeyEntry` hook exists, but `resign_chain` returns an unimplemented error;
  the hook retains the stored certificate and chain. The lower-level C++
  preservation helper is not wired into that Rust path.

## Platform policy and crypto ABI

Integrators must supply policy appropriate to their platform. keystore2 needs
read access to its configuration and supplied keybox. Package targeting also
needs permission to find `package_native` and call its Binder interface. No
vendor-specific policy, permissive mode, service definition or VINTF replacement
is supplied here. The existing AOSP service integration remains in place.

`compat/legacy_crypto.cpp` contains optional ABI adapters. They are excluded from
the default build. `UKEYSTORE_COMPAT_PBKDF2` supplies the AOSP-compatible PBKDF2
wrapper; `UKEYSTORE_COMPAT_LEGACY_STACK` forwards newer BoringSSL stack symbol
names to older exports. Add this file and the corresponding define only after
checking your target library's symbols and ABI. Enabling duplicate or incompatible
symbols can prevent keystore2 from starting. The legacy stack adapter is for
BoringSSL, not desktop OpenSSL.

## Scope

This distribution is source-only and has not been qualified as a universal ROM
component. It does not promise DEVICE or STRONG integrity, make software-backed
claims hardware-backed, reset fuses or change bootloader lock state.

TrickyStore's [README](https://github.com/5ec1cff/TrickyStore/blob/release/README.md)
and [security notes](https://github.com/5ec1cff/TrickyStore/blob/release/SECURITY.md)
describe a related certificate-chain approach with an installed module and more
runtime modes. Here integration is done at source/build time, and rebuilding the
ROM component is required to change the implementation. Configuration formats
are independent; API and feature parity are not claimed.
