// Copyright 2020 The Android Open Source Project
// SPDX-License-Identifier: Apache-2.0 AND MIT
// AOSP-derived portions: Apache-2.0. Original additions: MIT.
// Modified for the standalone ukeystore source distribution.

// Optional ABI adapters for ports with older system crypto libraries.
// Both adapters are disabled unless explicitly selected by the integrator.
// Never enable these when the platform already provides the same symbols.

#include <cstddef>
#include <cstdint>
#include <openssl/evp.h>
#include <openssl/stack.h>

extern "C" {
#ifdef UKEYSTORE_COMPAT_PBKDF2
void PBKDF2(uint8_t* key, size_t key_len, const char* pw, size_t pw_len,
            const uint8_t* salt) {
    static constexpr size_t kSaltSize = 16;
    static constexpr size_t kAes128Bytes = 16;
    const EVP_MD* digest = EVP_sha256();
    if (key_len == kAes128Bytes) digest = EVP_sha1();
    PKCS5_PBKDF2_HMAC(pw, static_cast<int>(pw_len),
                      salt, static_cast<int>(kSaltSize),
                      8192, digest,
                      static_cast<int>(key_len), key);
}
#endif

#ifdef UKEYSTORE_COMPAT_LEGACY_STACK
extern "C" OPENSSL_STACK* ukeystore_legacy_sk_new_null(void) __asm__("sk_new_null");
extern "C" size_t ukeystore_legacy_sk_push(OPENSSL_STACK*, void*) __asm__("sk_push");
extern "C" void ukeystore_legacy_sk_pop_free_ex(
    OPENSSL_STACK*, OPENSSL_sk_call_free_func, OPENSSL_sk_free_func)
    __asm__("sk_pop_free_ex");

OPENSSL_STACK* OPENSSL_sk_new_null(void) { return ukeystore_legacy_sk_new_null(); }
size_t OPENSSL_sk_push(OPENSSL_STACK* sk, void* p) { return ukeystore_legacy_sk_push(sk, p); }
void OPENSSL_sk_pop_free_ex(OPENSSL_STACK* sk, OPENSSL_sk_call_free_func call_free_func,
                            OPENSSL_sk_free_func free_func) {
    ukeystore_legacy_sk_pop_free_ex(sk, call_free_func, free_func);
}
#endif

}
