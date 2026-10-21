# ukeystore

Native attestation-chain handling for AOSP keystore2. Rust hooks and a C++ helper compiled into the system service, without a Magisk dependency.

- Select callers by UID, UID range or package name.
- Build an attestation certificate chain using a supplied profile and keybox.
- Keep the public key, challenge and application ID from the original request.
- Passthrough by default, with no callers selected.

This is a source integration for ROM developers, not a flashable module. It is pinned to one AOSP `system/security` revision; other versions need porting.

```sh
python3 tools/integrate.py --system-security /path/to/aosp/system/security
python3 tools/integrate.py --system-security /path/to/aosp/system/security --apply
```

The first command checks the checkout and patch. The second applies the sources. See [integration and configuration](docs/integration.md) for build dependencies and limitations.

No keys, certificates or device profiles are supplied. The example is inactive and its profile values are empty. This code does not guarantee a Play Integrity verdict or restore hardware trust. Stored-certificate rewriting through `getKeyEntry` is not implemented.

[TrickyStore](https://github.com/5ec1cff/TrickyStore) modifies attestation chains through an installed module. This implementation puts the changes directly in keystore2 and requires rebuilding the ROM component. It is not a drop-in replacement.

Host tests: `tests/run.sh` — requires Python 3, a C++17 compiler, OpenSSL development headers and `pkg-config`.

**Disclaimer:** Use at your own risk. You are responsible for your use of this software. The authors are not liable for misuse, damage or losses, to the extent permitted by law.

MIT for original additions. AOSP-derived portions retain Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
