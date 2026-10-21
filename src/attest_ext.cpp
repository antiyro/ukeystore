// Copyright 2020 The Android Open Source Project
// SPDX-License-Identifier: Apache-2.0 AND MIT
// AOSP-derived portions: Apache-2.0. Original additions: MIT.
// Modified for the standalone ukeystore source distribution.

// ASN.1 declarations adapted from AOSP KeyMint support/attestation_record.cpp.
// C ABI helpers for DER encoding, keybox loading and certificate-chain building.
// No keys or certificates are embedded in this source.

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

namespace ukeystore {

#define ASN1_INTEGER_SET STACK_OF(ASN1_INTEGER)

typedef struct km_root_of_trust {
    ASN1_OCTET_STRING* verified_boot_key;
    ASN1_BOOLEAN device_locked;
    ASN1_ENUMERATED* verified_boot_state;
    ASN1_OCTET_STRING* verified_boot_hash;
} KM_ROOT_OF_TRUST;

ASN1_SEQUENCE(KM_ROOT_OF_TRUST) = {
        ASN1_SIMPLE(KM_ROOT_OF_TRUST, verified_boot_key, ASN1_OCTET_STRING),
        ASN1_SIMPLE(KM_ROOT_OF_TRUST, device_locked, ASN1_BOOLEAN),
        ASN1_SIMPLE(KM_ROOT_OF_TRUST, verified_boot_state, ASN1_ENUMERATED),
        ASN1_SIMPLE(KM_ROOT_OF_TRUST, verified_boot_hash, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(KM_ROOT_OF_TRUST);
IMPLEMENT_ASN1_FUNCTIONS(KM_ROOT_OF_TRUST);

typedef struct km_auth_list {
    ASN1_INTEGER_SET* purpose;
    ASN1_INTEGER* algorithm;
    ASN1_INTEGER* key_size;
    ASN1_INTEGER_SET* digest;
    ASN1_INTEGER_SET* padding;
    ASN1_INTEGER* ec_curve;
    ASN1_INTEGER* rsa_public_exponent;
    ASN1_INTEGER_SET* mgf_digest;
    ASN1_NULL* rollback_resistance;
    ASN1_NULL* early_boot_only;
    ASN1_INTEGER* active_date_time;
    ASN1_INTEGER* origination_expire_date_time;
    ASN1_INTEGER* usage_expire_date_time;
    ASN1_INTEGER* usage_count_limit;
    ASN1_NULL* no_auth_required;
    ASN1_INTEGER* user_auth_type;
    ASN1_INTEGER* auth_timeout;
    ASN1_NULL* allow_while_on_body;
    ASN1_NULL* trusted_user_presence_required;
    ASN1_NULL* trusted_confirmation_required;
    ASN1_NULL* unlocked_device_required;
    ASN1_INTEGER* creation_date_time;
    ASN1_INTEGER* origin;
    KM_ROOT_OF_TRUST* root_of_trust;
    ASN1_INTEGER* os_version;
    ASN1_INTEGER* os_patchlevel;
    ASN1_OCTET_STRING* attestation_application_id;
    ASN1_OCTET_STRING* attestation_id_brand;
    ASN1_OCTET_STRING* attestation_id_device;
    ASN1_OCTET_STRING* attestation_id_product;
    ASN1_OCTET_STRING* attestation_id_serial;
    ASN1_OCTET_STRING* attestation_id_imei;
    ASN1_OCTET_STRING* attestation_id_meid;
    ASN1_OCTET_STRING* attestation_id_manufacturer;
    ASN1_OCTET_STRING* attestation_id_model;
    ASN1_INTEGER* vendor_patchlevel;
    ASN1_INTEGER* boot_patchlevel;
    ASN1_NULL* device_unique_attestation;
    ASN1_NULL* identity_credential;
    ASN1_OCTET_STRING* attestation_id_second_imei;
} KM_AUTH_LIST;

constexpr int T_PURPOSE              = 1;
constexpr int T_ALGORITHM            = 2;
constexpr int T_KEY_SIZE             = 3;
constexpr int T_DIGEST               = 5;
constexpr int T_PADDING              = 6;
constexpr int T_EC_CURVE             = 10;
constexpr int T_RSA_PUBLIC_EXPONENT  = 200;
constexpr int T_RSA_OAEP_MGF_DIGEST  = 203;
constexpr int T_ROLLBACK_RESISTANCE  = 303;
constexpr int T_EARLY_BOOT_ONLY      = 305;
constexpr int T_ACTIVE_DATETIME      = 400;
constexpr int T_ORIGINATION_EXPIRE   = 401;
constexpr int T_USAGE_EXPIRE         = 402;
constexpr int T_USAGE_COUNT_LIMIT    = 405;
constexpr int T_NO_AUTH_REQUIRED     = 503;
constexpr int T_USER_AUTH_TYPE       = 504;
constexpr int T_AUTH_TIMEOUT         = 505;
constexpr int T_ALLOW_WHILE_ON_BODY  = 506;
constexpr int T_TRUSTED_USER_PRES    = 507;
constexpr int T_TRUSTED_CONFIRM      = 508;
constexpr int T_UNLOCKED_DEVICE_REQ  = 509;
constexpr int T_CREATION_DATETIME    = 701;
constexpr int T_ORIGIN               = 702;
constexpr int T_ROOT_OF_TRUST        = 704;
constexpr int T_OS_VERSION           = 705;
constexpr int T_OS_PATCHLEVEL        = 706;
constexpr int T_ATT_APP_ID           = 709;
constexpr int T_ATT_ID_BRAND         = 710;
constexpr int T_ATT_ID_DEVICE        = 711;
constexpr int T_ATT_ID_PRODUCT       = 712;
constexpr int T_ATT_ID_SERIAL        = 713;
constexpr int T_ATT_ID_IMEI          = 714;
constexpr int T_ATT_ID_MEID          = 715;
constexpr int T_ATT_ID_MANUFACTURER  = 716;
constexpr int T_ATT_ID_MODEL         = 717;
constexpr int T_VENDOR_PATCHLEVEL    = 718;
constexpr int T_BOOT_PATCHLEVEL      = 719;
constexpr int T_DEVICE_UNIQUE_ATT    = 720;
constexpr int T_IDENTITY_CREDENTIAL  = 721;
constexpr int T_ATT_ID_SECOND_IMEI   = 723;

ASN1_SEQUENCE(KM_AUTH_LIST) = {
        ASN1_EXP_SET_OF_OPT(KM_AUTH_LIST, purpose, ASN1_INTEGER, T_PURPOSE),
        ASN1_EXP_OPT(KM_AUTH_LIST, algorithm, ASN1_INTEGER, T_ALGORITHM),
        ASN1_EXP_OPT(KM_AUTH_LIST, key_size, ASN1_INTEGER, T_KEY_SIZE),
        ASN1_EXP_SET_OF_OPT(KM_AUTH_LIST, digest, ASN1_INTEGER, T_DIGEST),
        ASN1_EXP_SET_OF_OPT(KM_AUTH_LIST, padding, ASN1_INTEGER, T_PADDING),
        ASN1_EXP_OPT(KM_AUTH_LIST, ec_curve, ASN1_INTEGER, T_EC_CURVE),
        ASN1_EXP_OPT(KM_AUTH_LIST, rsa_public_exponent, ASN1_INTEGER, T_RSA_PUBLIC_EXPONENT),
        ASN1_EXP_SET_OF_OPT(KM_AUTH_LIST, mgf_digest, ASN1_INTEGER, T_RSA_OAEP_MGF_DIGEST),
        ASN1_EXP_OPT(KM_AUTH_LIST, rollback_resistance, ASN1_NULL, T_ROLLBACK_RESISTANCE),
        ASN1_EXP_OPT(KM_AUTH_LIST, early_boot_only, ASN1_NULL, T_EARLY_BOOT_ONLY),
        ASN1_EXP_OPT(KM_AUTH_LIST, active_date_time, ASN1_INTEGER, T_ACTIVE_DATETIME),
        ASN1_EXP_OPT(KM_AUTH_LIST, origination_expire_date_time, ASN1_INTEGER, T_ORIGINATION_EXPIRE),
        ASN1_EXP_OPT(KM_AUTH_LIST, usage_expire_date_time, ASN1_INTEGER, T_USAGE_EXPIRE),
        ASN1_EXP_OPT(KM_AUTH_LIST, usage_count_limit, ASN1_INTEGER, T_USAGE_COUNT_LIMIT),
        ASN1_EXP_OPT(KM_AUTH_LIST, no_auth_required, ASN1_NULL, T_NO_AUTH_REQUIRED),
        ASN1_EXP_OPT(KM_AUTH_LIST, user_auth_type, ASN1_INTEGER, T_USER_AUTH_TYPE),
        ASN1_EXP_OPT(KM_AUTH_LIST, auth_timeout, ASN1_INTEGER, T_AUTH_TIMEOUT),
        ASN1_EXP_OPT(KM_AUTH_LIST, allow_while_on_body, ASN1_NULL, T_ALLOW_WHILE_ON_BODY),
        ASN1_EXP_OPT(KM_AUTH_LIST, trusted_user_presence_required, ASN1_NULL, T_TRUSTED_USER_PRES),
        ASN1_EXP_OPT(KM_AUTH_LIST, trusted_confirmation_required, ASN1_NULL, T_TRUSTED_CONFIRM),
        ASN1_EXP_OPT(KM_AUTH_LIST, unlocked_device_required, ASN1_NULL, T_UNLOCKED_DEVICE_REQ),
        ASN1_EXP_OPT(KM_AUTH_LIST, creation_date_time, ASN1_INTEGER, T_CREATION_DATETIME),
        ASN1_EXP_OPT(KM_AUTH_LIST, origin, ASN1_INTEGER, T_ORIGIN),
        ASN1_EXP_OPT(KM_AUTH_LIST, root_of_trust, KM_ROOT_OF_TRUST, T_ROOT_OF_TRUST),
        ASN1_EXP_OPT(KM_AUTH_LIST, os_version, ASN1_INTEGER, T_OS_VERSION),
        ASN1_EXP_OPT(KM_AUTH_LIST, os_patchlevel, ASN1_INTEGER, T_OS_PATCHLEVEL),
        ASN1_EXP_OPT(KM_AUTH_LIST, attestation_application_id, ASN1_OCTET_STRING, T_ATT_APP_ID),
        ASN1_EXP_OPT(KM_AUTH_LIST, attestation_id_brand, ASN1_OCTET_STRING, T_ATT_ID_BRAND),
        ASN1_EXP_OPT(KM_AUTH_LIST, attestation_id_device, ASN1_OCTET_STRING, T_ATT_ID_DEVICE),
        ASN1_EXP_OPT(KM_AUTH_LIST, attestation_id_product, ASN1_OCTET_STRING, T_ATT_ID_PRODUCT),
        ASN1_EXP_OPT(KM_AUTH_LIST, attestation_id_serial, ASN1_OCTET_STRING, T_ATT_ID_SERIAL),
        ASN1_EXP_OPT(KM_AUTH_LIST, attestation_id_imei, ASN1_OCTET_STRING, T_ATT_ID_IMEI),
        ASN1_EXP_OPT(KM_AUTH_LIST, attestation_id_meid, ASN1_OCTET_STRING, T_ATT_ID_MEID),
        ASN1_EXP_OPT(KM_AUTH_LIST, attestation_id_manufacturer, ASN1_OCTET_STRING, T_ATT_ID_MANUFACTURER),
        ASN1_EXP_OPT(KM_AUTH_LIST, attestation_id_model, ASN1_OCTET_STRING, T_ATT_ID_MODEL),
        ASN1_EXP_OPT(KM_AUTH_LIST, vendor_patchlevel, ASN1_INTEGER, T_VENDOR_PATCHLEVEL),
        ASN1_EXP_OPT(KM_AUTH_LIST, boot_patchlevel, ASN1_INTEGER, T_BOOT_PATCHLEVEL),
        ASN1_EXP_OPT(KM_AUTH_LIST, device_unique_attestation, ASN1_NULL, T_DEVICE_UNIQUE_ATT),
        ASN1_EXP_OPT(KM_AUTH_LIST, identity_credential, ASN1_NULL, T_IDENTITY_CREDENTIAL),
        ASN1_EXP_OPT(KM_AUTH_LIST, attestation_id_second_imei, ASN1_OCTET_STRING, T_ATT_ID_SECOND_IMEI),
} ASN1_SEQUENCE_END(KM_AUTH_LIST);
IMPLEMENT_ASN1_FUNCTIONS(KM_AUTH_LIST);

typedef struct km_key_description {
    ASN1_INTEGER* attestation_version;
    ASN1_ENUMERATED* attestation_security_level;
    ASN1_INTEGER* keymint_version;
    ASN1_ENUMERATED* keymint_security_level;
    ASN1_OCTET_STRING* attestation_challenge;
    ASN1_OCTET_STRING* unique_id;
    KM_AUTH_LIST* software_enforced;
    KM_AUTH_LIST* tee_enforced;
} KM_KEY_DESCRIPTION;

ASN1_SEQUENCE(KM_KEY_DESCRIPTION) = {
        ASN1_SIMPLE(KM_KEY_DESCRIPTION, attestation_version, ASN1_INTEGER),
        ASN1_SIMPLE(KM_KEY_DESCRIPTION, attestation_security_level, ASN1_ENUMERATED),
        ASN1_SIMPLE(KM_KEY_DESCRIPTION, keymint_version, ASN1_INTEGER),
        ASN1_SIMPLE(KM_KEY_DESCRIPTION, keymint_security_level, ASN1_ENUMERATED),
        ASN1_SIMPLE(KM_KEY_DESCRIPTION, attestation_challenge, ASN1_OCTET_STRING),
        ASN1_SIMPLE(KM_KEY_DESCRIPTION, unique_id, ASN1_OCTET_STRING),
        ASN1_SIMPLE(KM_KEY_DESCRIPTION, software_enforced, KM_AUTH_LIST),
        ASN1_SIMPLE(KM_KEY_DESCRIPTION, tee_enforced, KM_AUTH_LIST),
} ASN1_SEQUENCE_END(KM_KEY_DESCRIPTION);
IMPLEMENT_ASN1_FUNCTIONS(KM_KEY_DESCRIPTION);

static const char kAsn1TokenOid[] = "1.3.6.1.4.1.11129.2.1.17";

static bool set_octet(ASN1_OCTET_STRING** dst, const uint8_t* data, size_t len) {
    if (data == nullptr || len == 0) return true;
    ASN1_OCTET_STRING* s = ASN1_OCTET_STRING_new();
    if (s == nullptr) return false;
    if (!ASN1_OCTET_STRING_set(s, data, static_cast<int>(len))) {
        ASN1_OCTET_STRING_free(s);
        return false;
    }
    if (*dst) ASN1_OCTET_STRING_free(*dst);
    *dst = s;
    return true;
}

static bool set_int(ASN1_INTEGER** dst, int64_t value, bool present) {
    if (!present) return true;
    ASN1_INTEGER* i = ASN1_INTEGER_new();
    if (i == nullptr) return false;
    if (!ASN1_INTEGER_set_int64(i, value)) {
        ASN1_INTEGER_free(i);
        return false;
    }
    if (*dst) ASN1_INTEGER_free(*dst);
    *dst = i;
    return true;
}

static bool set_enum(ASN1_ENUMERATED** dst, int64_t value) {
    ASN1_ENUMERATED* e = ASN1_ENUMERATED_new();
    if (e == nullptr) return false;
    if (!ASN1_ENUMERATED_set(e, static_cast<long>(value))) {
        ASN1_ENUMERATED_free(e);
        return false;
    }
    if (*dst) ASN1_ENUMERATED_free(*dst);
    *dst = e;
    return true;
}

static bool push_int_set(ASN1_INTEGER_SET** dst, const int64_t* values, size_t count) {
    if (values == nullptr || count == 0) return true;
    ASN1_INTEGER_SET* set = sk_ASN1_INTEGER_new_null();
    if (set == nullptr) return false;
    for (size_t i = 0; i < count; ++i) {
        ASN1_INTEGER* val = ASN1_INTEGER_new();
        if (val == nullptr || !ASN1_INTEGER_set_int64(val, values[i]) ||
            !sk_ASN1_INTEGER_push(set, val)) {
            if (val) ASN1_INTEGER_free(val);
            sk_ASN1_INTEGER_pop_free(set, ASN1_INTEGER_free);
            return false;
        }
    }
    if (*dst) sk_ASN1_INTEGER_pop_free(*dst, ASN1_INTEGER_free);
    *dst = set;
    return true;
}

}

extern "C" {

struct UkeystoreAttestParams {
    int32_t attestation_version;
    int32_t attestation_security_level;
    int32_t keymint_version;
    int32_t keymint_security_level;
    const uint8_t* attestation_challenge; size_t attestation_challenge_len;
    const uint8_t* unique_id;            size_t unique_id_len;
    const uint8_t* attestation_application_id; size_t attestation_application_id_len;
    int64_t creation_datetime;
    const int64_t* purpose;              size_t purpose_count;
    int32_t algorithm;
    int32_t key_size;
    const int64_t* digest;               size_t digest_count;
    const int64_t* padding;              size_t padding_count;
    int32_t ec_curve;
    int32_t origin;
    int32_t no_auth_required;
    int32_t unlocked_device_required;
    int32_t rollback_resistance;
    const uint8_t* verified_boot_key;    size_t verified_boot_key_len;
    int32_t device_locked;
    int32_t verified_boot_state;
    const uint8_t* verified_boot_hash;   size_t verified_boot_hash_len;
    int32_t os_version;
    int32_t os_patch_level;
    int32_t vendor_patch_level;
    int32_t boot_patch_level;
    const uint8_t* attestation_id_brand;        size_t attestation_id_brand_len;
    const uint8_t* attestation_id_device;       size_t attestation_id_device_len;
    const uint8_t* attestation_id_product;      size_t attestation_id_product_len;
    const uint8_t* attestation_id_serial;       size_t attestation_id_serial_len;
    const uint8_t* attestation_id_imei;         size_t attestation_id_imei_len;
    const uint8_t* attestation_id_meid;         size_t attestation_id_meid_len;
    const uint8_t* attestation_id_manufacturer; size_t attestation_id_manufacturer_len;
    const uint8_t* attestation_id_model;        size_t attestation_id_model_len;
    const uint8_t* attestation_id_second_imei;  size_t attestation_id_second_imei_len;
};

int ukeystore_build_attest_record(const UkeystoreAttestParams* p, uint8_t** out, size_t* out_len) {
    using namespace ukeystore;
    if (p == nullptr || out == nullptr || out_len == nullptr) return -1;

    std::unique_ptr<KM_KEY_DESCRIPTION, void(*)(KM_KEY_DESCRIPTION*)> kd(
        KM_KEY_DESCRIPTION_new(), KM_KEY_DESCRIPTION_free);
    if (!kd) return -1;

    if (!set_int(&kd->attestation_version, p->attestation_version, true)) return -1;
    if (!set_enum(&kd->attestation_security_level, p->attestation_security_level)) return -1;
    if (!set_int(&kd->keymint_version, p->keymint_version, true)) return -1;
    if (!set_enum(&kd->keymint_security_level, p->keymint_security_level)) return -1;
    if (!set_octet(&kd->attestation_challenge, p->attestation_challenge, p->attestation_challenge_len)) return -1;
    if (!set_octet(&kd->unique_id, p->unique_id, p->unique_id_len)) return -1;

    if (!set_octet(&kd->software_enforced->attestation_application_id,
                   p->attestation_application_id, p->attestation_application_id_len)) return -1;
    if (p->creation_datetime != 0) {
        if (!set_int(&kd->software_enforced->creation_date_time, p->creation_datetime, true)) return -1;
    }

    KM_AUTH_LIST* tee = kd->tee_enforced;
    if (!push_int_set(&tee->purpose, p->purpose, p->purpose_count)) return -1;
    if (p->algorithm != 0 && !set_int(&tee->algorithm, p->algorithm, true)) return -1;
    if (p->key_size != 0 && !set_int(&tee->key_size, p->key_size, true)) return -1;
    if (!push_int_set(&tee->digest, p->digest, p->digest_count)) return -1;
    if (!push_int_set(&tee->padding, p->padding, p->padding_count)) return -1;
    if (p->ec_curve >= 0 && !set_int(&tee->ec_curve, p->ec_curve, true)) return -1;
    if (p->no_auth_required) {
        tee->no_auth_required = ASN1_NULL_new();
        if (!tee->no_auth_required) return -1;
    }
    if (p->unlocked_device_required) {
        tee->unlocked_device_required = ASN1_NULL_new();
        if (!tee->unlocked_device_required) return -1;
    }
    if (p->rollback_resistance) {
        tee->rollback_resistance = ASN1_NULL_new();
        if (!tee->rollback_resistance) return -1;
    }
    if (p->origin >= 0 && !set_int(&tee->origin, p->origin, true)) return -1;

    KM_ROOT_OF_TRUST* rot = KM_ROOT_OF_TRUST_new();
    if (!rot) return -1;
    if (!set_octet(&rot->verified_boot_key, p->verified_boot_key, p->verified_boot_key_len)) {
        KM_ROOT_OF_TRUST_free(rot); return -1;
    }
    rot->device_locked = p->device_locked ? 0xFF : 0x00;
    if (!ASN1_ENUMERATED_set(rot->verified_boot_state, p->verified_boot_state)) {
        KM_ROOT_OF_TRUST_free(rot); return -1;
    }
    if (!set_octet(&rot->verified_boot_hash, p->verified_boot_hash, p->verified_boot_hash_len)) {
        KM_ROOT_OF_TRUST_free(rot); return -1;
    }
    if (tee->root_of_trust) KM_ROOT_OF_TRUST_free(tee->root_of_trust);
    tee->root_of_trust = rot;

    if (p->os_version != 0 && !set_int(&tee->os_version, p->os_version, true)) return -1;
    if (p->os_patch_level != 0 && !set_int(&tee->os_patchlevel, p->os_patch_level, true)) return -1;
    if (p->vendor_patch_level != 0 && !set_int(&tee->vendor_patchlevel, p->vendor_patch_level, true)) return -1;
    if (p->boot_patch_level != 0 && !set_int(&tee->boot_patchlevel, p->boot_patch_level, true)) return -1;

    if (!set_octet(&tee->attestation_id_brand,        p->attestation_id_brand,        p->attestation_id_brand_len)) return -1;
    if (!set_octet(&tee->attestation_id_device,       p->attestation_id_device,       p->attestation_id_device_len)) return -1;
    if (!set_octet(&tee->attestation_id_product,      p->attestation_id_product,      p->attestation_id_product_len)) return -1;
    if (!set_octet(&tee->attestation_id_serial,       p->attestation_id_serial,       p->attestation_id_serial_len)) return -1;
    if (!set_octet(&tee->attestation_id_imei,         p->attestation_id_imei,         p->attestation_id_imei_len)) return -1;
    if (!set_octet(&tee->attestation_id_meid,         p->attestation_id_meid,         p->attestation_id_meid_len)) return -1;
    if (!set_octet(&tee->attestation_id_manufacturer, p->attestation_id_manufacturer, p->attestation_id_manufacturer_len)) return -1;
    if (!set_octet(&tee->attestation_id_model,        p->attestation_id_model,        p->attestation_id_model_len)) return -1;
    if (!set_octet(&tee->attestation_id_second_imei,  p->attestation_id_second_imei,  p->attestation_id_second_imei_len)) return -1;

    int len = i2d_KM_KEY_DESCRIPTION(kd.get(), nullptr);
    if (len < 0) return -1;
    uint8_t* buf = static_cast<uint8_t*>(std::malloc(static_cast<size_t>(len)));
    if (buf == nullptr) return -1;
    uint8_t* p_buf = buf;
    int written = i2d_KM_KEY_DESCRIPTION(kd.get(), &p_buf);
    if (written != len) { std::free(buf); return -1; }
    *out = buf;
    *out_len = static_cast<size_t>(len);
    return 0;
}

int ukeystore_roundtrip_attest_record(const uint8_t* in, size_t in_len,
                                  uint8_t** out, size_t* out_len) {
    using namespace ukeystore;
    if (in == nullptr || in_len == 0 || out == nullptr || out_len == nullptr) return -1;
    const uint8_t* cursor = in;
    KM_KEY_DESCRIPTION* kd = d2i_KM_KEY_DESCRIPTION(nullptr, &cursor, static_cast<long>(in_len));
    if (kd == nullptr) return -1;
    int len = i2d_KM_KEY_DESCRIPTION(kd, nullptr);
    if (len < 0) { KM_KEY_DESCRIPTION_free(kd); return -1; }
    uint8_t* buf = static_cast<uint8_t*>(std::malloc(static_cast<size_t>(len)));
    if (buf == nullptr) { KM_KEY_DESCRIPTION_free(kd); return -1; }
    uint8_t* p_buf = buf;
    int written = i2d_KM_KEY_DESCRIPTION(kd, &p_buf);
    KM_KEY_DESCRIPTION_free(kd);
    if (written != len) { std::free(buf); return -1; }
    *out = buf;
    *out_len = static_cast<size_t>(len);
    return 0;
}

int ukeystore_build_attest_extension(const UkeystoreAttestParams* p, uint8_t** out, size_t* out_len) {
    using namespace ukeystore;
    if (p == nullptr || out == nullptr || out_len == nullptr) return -1;

    uint8_t* inner = nullptr;
    size_t inner_len = 0;
    if (ukeystore_build_attest_record(p, &inner, &inner_len) != 0) return -1;

    ASN1_OBJECT* oid = OBJ_txt2obj(kAsn1TokenOid, 1);
    if (oid == nullptr) { std::free(inner); return -1; }

    ASN1_OCTET_STRING* wrap = ASN1_OCTET_STRING_new();
    if (wrap == nullptr || !ASN1_OCTET_STRING_set(wrap, inner, static_cast<int>(inner_len))) {
        if (wrap) ASN1_OCTET_STRING_free(wrap);
        ASN1_OBJECT_free(oid);
        std::free(inner);
        return -1;
    }
    std::free(inner);

    X509_EXTENSION* ext = X509_EXTENSION_create_by_OBJ(nullptr, oid, /*critical*/ 0, wrap);
    ASN1_OBJECT_free(oid);
    ASN1_OCTET_STRING_free(wrap);
    if (ext == nullptr) return -1;

    int len = i2d_X509_EXTENSION(ext, nullptr);
    if (len < 0) { X509_EXTENSION_free(ext); return -1; }
    uint8_t* buf = static_cast<uint8_t*>(std::malloc(static_cast<size_t>(len)));
    if (buf == nullptr) { X509_EXTENSION_free(ext); return -1; }
    uint8_t* p_buf = buf;
    int written = i2d_X509_EXTENSION(ext, &p_buf);
    X509_EXTENSION_free(ext);
    if (written != len) { std::free(buf); return -1; }
    *out = buf;
    *out_len = static_cast<size_t>(len);
    return 0;
}

}

namespace ukeystore {

struct KeyboxEntry {
    std::string algorithm;
    EVP_PKEY* private_key;
    std::vector<X509*> chain;
};

struct KeyboxHandle {
    std::vector<KeyboxEntry> entries;
};

static std::string slurp_file(const char* path) {
    std::FILE* f = std::fopen(path, "rb");
    if (f == nullptr) return std::string();
    std::fseek(f, 0, SEEK_END);
    long sz = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 16 * 1024 * 1024) { std::fclose(f); return std::string(); }
    std::string out(static_cast<size_t>(sz), '\0');
    if (std::fread(&out[0], 1, static_cast<size_t>(sz), f) != static_cast<size_t>(sz)) {
        std::fclose(f); return std::string();
    }
    std::fclose(f);
    return out;
}

static bool find_tag(const std::string& s, const std::string& tag, size_t from,
                     size_t* content_begin, size_t* content_end, size_t* after_close) {
    std::string open = "<" + tag;
    std::string close = "</" + tag + ">";
    size_t p = s.find(open, from);
    if (p == std::string::npos) return false;
    size_t gt = s.find('>', p);
    if (gt == std::string::npos) return false;
    if (s[gt - 1] == '/') {
        *content_begin = gt + 1;
        *content_end = gt + 1;
        *after_close = gt + 1;
        return true;
    }
    size_t cb = gt + 1;
    size_t ce = s.find(close, cb);
    if (ce == std::string::npos) return false;
    *content_begin = cb;
    *content_end = ce;
    *after_close = ce + close.size();
    return true;
}

static std::string read_algo_attr(const std::string& s, size_t tag_open_at) {
    size_t gt = s.find('>', tag_open_at);
    if (gt == std::string::npos) return "";
    std::string slice = s.substr(tag_open_at, gt - tag_open_at);
    size_t at = slice.find("algorithm=");
    if (at == std::string::npos) return "";
    size_t q = slice.find('"', at);
    if (q == std::string::npos) return "";
    size_t q2 = slice.find('"', q + 1);
    if (q2 == std::string::npos) return "";
    return slice.substr(q + 1, q2 - q - 1);
}

static EVP_PKEY* parse_pem_privkey(const std::string& pem) {
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (bio == nullptr) return nullptr;
    EVP_PKEY* pk = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return pk;
}

static X509* parse_pem_cert(const std::string& pem) {
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (bio == nullptr) return nullptr;
    X509* c = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return c;
}

}

extern "C" {

int ukeystore_keybox_load(const char* path, void** out_handle) {
    using namespace ukeystore;
    if (path == nullptr || out_handle == nullptr) return -1;
    std::string xml = slurp_file(path);
    if (xml.empty()) return -1;

    auto* h = new KeyboxHandle{};
    size_t cb, ce, ac;
    size_t scan = 0;
    while (find_tag(xml, "Key", scan, &cb, &ce, &ac)) {
        size_t tag_open_at = xml.rfind("<Key", cb);
        std::string algo = read_algo_attr(xml, tag_open_at);
        KeyboxEntry entry{};
        entry.algorithm = algo;

        std::string body = xml.substr(cb, ce - cb);
        size_t pk_b, pk_e, pk_ac;
        if (find_tag(body, "PrivateKey", 0, &pk_b, &pk_e, &pk_ac)) {
            std::string pem = body.substr(pk_b, pk_e - pk_b);
            entry.private_key = parse_pem_privkey(pem);
        }

        size_t chain_b, chain_e, chain_ac;
        if (find_tag(body, "CertificateChain", 0, &chain_b, &chain_e, &chain_ac)) {
            std::string chain = body.substr(chain_b, chain_e - chain_b);
            size_t cert_scan = 0;
            size_t crt_b, crt_e, crt_ac;
            while (find_tag(chain, "Certificate", cert_scan, &crt_b, &crt_e, &crt_ac)) {
                std::string pem = chain.substr(crt_b, crt_e - crt_b);
                X509* c = parse_pem_cert(pem);
                if (c) entry.chain.push_back(c);
                cert_scan = crt_ac;
            }
        }

        if (entry.private_key) {
            h->entries.push_back(std::move(entry));
        } else {
            for (auto* c : entry.chain) X509_free(c);
        }
        scan = ac;
    }

    if (h->entries.empty()) {
        delete h;
        return -1;
    }
    *out_handle = h;
    return 0;
}

void ukeystore_keybox_free(void* handle) {
    using namespace ukeystore;
    if (handle == nullptr) return;
    auto* h = static_cast<KeyboxHandle*>(handle);
    for (auto& e : h->entries) {
        if (e.private_key) EVP_PKEY_free(e.private_key);
        for (auto* c : e.chain) X509_free(c);
    }
    delete h;
}

int ukeystore_keybox_entry_count(void* handle) {
    using namespace ukeystore;
    if (handle == nullptr) return 0;
    return static_cast<int>(static_cast<KeyboxHandle*>(handle)->entries.size());
}

int ukeystore_keybox_chain_count(void* handle, int idx) {
    using namespace ukeystore;
    if (handle == nullptr || idx < 0) return -1;
    auto* h = static_cast<KeyboxHandle*>(handle);
    if (idx >= static_cast<int>(h->entries.size())) return -1;
    return static_cast<int>(h->entries[idx].chain.size());
}

int ukeystore_keybox_chain_cert(void* handle, int idx, int n,
                            uint8_t** out, size_t* out_len) {
    using namespace ukeystore;
    if (handle == nullptr || idx < 0 || n < 0 || out == nullptr || out_len == nullptr) return -1;
    auto* h = static_cast<KeyboxHandle*>(handle);
    if (idx >= static_cast<int>(h->entries.size())) return -1;
    if (n >= static_cast<int>(h->entries[idx].chain.size())) return -1;
    X509* c = h->entries[idx].chain[n];
    int len = i2d_X509(c, nullptr);
    if (len < 0) return -1;
    uint8_t* buf = static_cast<uint8_t*>(std::malloc(static_cast<size_t>(len)));
    if (buf == nullptr) return -1;
    uint8_t* p = buf;
    if (i2d_X509(c, &p) != len) { std::free(buf); return -1; }
    *out = buf;
    *out_len = static_cast<size_t>(len);
    return 0;
}

static const EVP_MD* digest_for_key(EVP_PKEY* k) {
    int t = EVP_PKEY_base_id(k);
    if (t == EVP_PKEY_EC) return EVP_sha256();
    if (t == EVP_PKEY_RSA) return EVP_sha256();
    return EVP_sha256();
}

int ukeystore_synth_chain(void* handle,
                      const char* algorithm_pref,
                      const uint8_t* leaf_pubkey_der, size_t leaf_pubkey_der_len,
                      const UkeystoreAttestParams* p,
                      uint8_t*** out_ders, size_t** out_lens, int* out_count) {
    using namespace ukeystore;
    if (handle == nullptr || leaf_pubkey_der == nullptr || p == nullptr ||
        out_ders == nullptr || out_lens == nullptr || out_count == nullptr) return -1;

    auto* h = static_cast<KeyboxHandle*>(handle);
    if (h->entries.empty()) return -1;

    KeyboxEntry* sel = nullptr;
    std::string pref = algorithm_pref ? algorithm_pref : "";
    for (auto& e : h->entries) {
        if (e.algorithm == pref) { sel = &e; break; }
    }
    if (sel == nullptr) sel = &h->entries.front();
    if (sel->chain.empty()) return -1;

    const uint8_t* spki_cursor = leaf_pubkey_der;
    EVP_PKEY* leaf_pubkey = d2i_PUBKEY(nullptr, &spki_cursor, static_cast<long>(leaf_pubkey_der_len));
    if (leaf_pubkey == nullptr) return -1;

    X509* leaf = X509_new();
    if (leaf == nullptr) { EVP_PKEY_free(leaf_pubkey); return -1; }

    X509_set_version(leaf, 2);

    if (!ASN1_INTEGER_set(X509_get_serialNumber(leaf), 1)) {
        X509_free(leaf); EVP_PKEY_free(leaf_pubkey); return -1;
    }

    {
        ASN1_TIME* nb = ASN1_TIME_set(nullptr, static_cast<time_t>(0));
        ASN1_TIME* na = ASN1_TIME_set(nullptr, static_cast<time_t>(2461449600LL));
        if (nb) { X509_set_notBefore(leaf, nb); ASN1_TIME_free(nb); }
        if (na) { X509_set_notAfter(leaf, na); ASN1_TIME_free(na); }
    }

    X509_NAME* subj = X509_NAME_new();
    if (subj == nullptr) { X509_free(leaf); EVP_PKEY_free(leaf_pubkey); return -1; }
    if (!X509_NAME_add_entry_by_txt(subj, "CN", V_ASN1_PRINTABLESTRING,
            reinterpret_cast<const uint8_t*>("Android Keystore Key"), -1, -1, 0) ||
        !X509_set_subject_name(leaf, subj)) {
        X509_NAME_free(subj); X509_free(leaf); EVP_PKEY_free(leaf_pubkey); return -1;
    }
    X509_NAME_free(subj);

    X509_NAME* issuer_name = X509_get_subject_name(sel->chain.front());
    if (issuer_name != nullptr) X509_set_issuer_name(leaf, issuer_name);

    X509_set_pubkey(leaf, leaf_pubkey);
    EVP_PKEY_free(leaf_pubkey);

    {
        static const uint8_t kDigitalSignatureDer[] = {0x03, 0x02, 0x07, 0x80};
        ASN1_OBJECT* oid = OBJ_txt2obj("2.5.29.15", 1);
        ASN1_OCTET_STRING* value = ASN1_OCTET_STRING_new();
        if (oid == nullptr || value == nullptr ||
            !ASN1_OCTET_STRING_set(value, kDigitalSignatureDer,
                                   static_cast<int>(sizeof(kDigitalSignatureDer)))) {
            if (oid) ASN1_OBJECT_free(oid);
            if (value) ASN1_OCTET_STRING_free(value);
            X509_free(leaf); return -1;
        }
        X509_EXTENSION* key_usage = X509_EXTENSION_create_by_OBJ(nullptr, oid, 1, value);
        ASN1_OBJECT_free(oid);
        ASN1_OCTET_STRING_free(value);
        if (key_usage == nullptr || !X509_add_ext(leaf, key_usage, -1)) {
            if (key_usage) X509_EXTENSION_free(key_usage);
            X509_free(leaf); return -1;
        }
        X509_EXTENSION_free(key_usage);
    }

    {
        uint8_t* ext_der = nullptr; size_t ext_len = 0;
        if (ukeystore_build_attest_extension(p, &ext_der, &ext_len) != 0) {
            X509_free(leaf); return -1;
        }
        const uint8_t* ext_cur = ext_der;
        X509_EXTENSION* ext = d2i_X509_EXTENSION(nullptr, &ext_cur, static_cast<long>(ext_len));
        std::free(ext_der);
        if (ext == nullptr) { X509_free(leaf); return -1; }
        X509_add_ext(leaf, ext, -1);
        X509_EXTENSION_free(ext);
    }

    const EVP_MD* md = digest_for_key(sel->private_key);
    if (X509_sign(leaf, sel->private_key, md) == 0) {
        X509_free(leaf); return -1;
    }

    int total = 1 + static_cast<int>(sel->chain.size());
    auto** ders = static_cast<uint8_t**>(std::malloc(sizeof(uint8_t*) * total));
    auto* lens = static_cast<size_t*>(std::malloc(sizeof(size_t) * total));
    if (ders == nullptr || lens == nullptr) {
        if (ders) std::free(ders);
        if (lens) std::free(lens);
        X509_free(leaf); return -1;
    }
    for (int i = 0; i < total; ++i) { ders[i] = nullptr; lens[i] = 0; }

    auto encode = [](X509* c, uint8_t** out, size_t* out_len) -> bool {
        int n = i2d_X509(c, nullptr);
        if (n < 0) return false;
        *out = static_cast<uint8_t*>(std::malloc(static_cast<size_t>(n)));
        if (*out == nullptr) return false;
        uint8_t* p = *out;
        if (i2d_X509(c, &p) != n) { std::free(*out); *out = nullptr; return false; }
        *out_len = static_cast<size_t>(n);
        return true;
    };

    if (!encode(leaf, &ders[0], &lens[0])) {
        X509_free(leaf); std::free(ders); std::free(lens); return -1;
    }
    X509_free(leaf);

    for (size_t i = 0; i < sel->chain.size(); ++i) {
        if (!encode(sel->chain[i], &ders[i + 1], &lens[i + 1])) {
            for (size_t j = 0; j <= i; ++j) std::free(ders[j]);
            std::free(ders); std::free(lens);
            return -1;
        }
    }

    *out_ders = ders;
    *out_lens = lens;
    *out_count = total;
    return 0;
}

struct UkeystoreRotOverride {
    const uint8_t* verified_boot_key;  size_t verified_boot_key_len;
    int32_t device_locked;
    int32_t verified_boot_state;
    const uint8_t* verified_boot_hash; size_t verified_boot_hash_len;
};
int ukeystore_hack_chain(void* handle,
                     const char* algorithm_pref,
                     const uint8_t* genuine_leaf_der, size_t genuine_leaf_der_len,
                     const UkeystoreRotOverride* rot,
                     uint8_t*** out_ders, size_t** out_lens, int* out_count) {
    using namespace ukeystore;
    if (handle == nullptr || genuine_leaf_der == nullptr || rot == nullptr ||
        out_ders == nullptr || out_lens == nullptr || out_count == nullptr) return -1;

    auto* h = static_cast<KeyboxHandle*>(handle);
    if (h->entries.empty()) return -1;

    KeyboxEntry* sel = nullptr;
    std::string pref = algorithm_pref ? algorithm_pref : "";
    for (auto& e : h->entries) { if (e.algorithm == pref) { sel = &e; break; } }
    if (sel == nullptr) sel = &h->entries.front();
    if (sel->chain.empty() || sel->private_key == nullptr) return -1;

    const uint8_t* leaf_cur = genuine_leaf_der;
    X509* leaf = d2i_X509(nullptr, &leaf_cur, static_cast<long>(genuine_leaf_der_len));
    if (leaf == nullptr) return -1;

    ASN1_OBJECT* oid = OBJ_txt2obj(kAsn1TokenOid, 1);
    if (oid == nullptr) { X509_free(leaf); return -1; }
    int ext_idx = X509_get_ext_by_OBJ(leaf, oid, -1);
    ASN1_OBJECT_free(oid);
    if (ext_idx < 0) { X509_free(leaf); return -1; }
    X509_EXTENSION* ext = X509_get_ext(leaf, ext_idx);
    ASN1_OCTET_STRING* ext_data = ext ? X509_EXTENSION_get_data(ext) : nullptr;
    if (ext_data == nullptr) { X509_free(leaf); return -1; }

    const uint8_t* kd_cur = ext_data->data;
    KM_KEY_DESCRIPTION* kd = d2i_KM_KEY_DESCRIPTION(nullptr, &kd_cur,
                                                    static_cast<long>(ext_data->length));
    if (kd == nullptr) { X509_free(leaf); return -1; }

    KM_AUTH_LIST* tee = kd->tee_enforced;
    if (tee == nullptr) { KM_KEY_DESCRIPTION_free(kd); X509_free(leaf); return -1; }
    KM_ROOT_OF_TRUST* nr = KM_ROOT_OF_TRUST_new();
    if (nr == nullptr) { KM_KEY_DESCRIPTION_free(kd); X509_free(leaf); return -1; }
    bool ok = set_octet(&nr->verified_boot_key, rot->verified_boot_key, rot->verified_boot_key_len)
           && set_octet(&nr->verified_boot_hash, rot->verified_boot_hash, rot->verified_boot_hash_len)
           && ASN1_ENUMERATED_set(nr->verified_boot_state, rot->verified_boot_state);
    nr->device_locked = rot->device_locked ? 0xFF : 0x00;
    if (!ok) { KM_ROOT_OF_TRUST_free(nr); KM_KEY_DESCRIPTION_free(kd); X509_free(leaf); return -1; }
    if (tee->root_of_trust) KM_ROOT_OF_TRUST_free(tee->root_of_trust);
    tee->root_of_trust = nr;

    uint8_t* new_kd = nullptr;
    int new_kd_len = i2d_KM_KEY_DESCRIPTION(kd, &new_kd);
    KM_KEY_DESCRIPTION_free(kd);
    if (new_kd_len < 0 || new_kd == nullptr) { X509_free(leaf); return -1; }
    ASN1_OCTET_STRING* new_ext_os = ASN1_OCTET_STRING_new();
    if (new_ext_os == nullptr || !ASN1_OCTET_STRING_set(new_ext_os, new_kd, new_kd_len)) {
        if (new_ext_os) ASN1_OCTET_STRING_free(new_ext_os);
        OPENSSL_free(new_kd); X509_free(leaf); return -1;
    }
    OPENSSL_free(new_kd);
    if (!X509_EXTENSION_set_data(ext, new_ext_os)) {
        ASN1_OCTET_STRING_free(new_ext_os); X509_free(leaf); return -1;
    }
    ASN1_OCTET_STRING_free(new_ext_os);

    X509_NAME* issuer_name = X509_get_subject_name(sel->chain.front());
    if (issuer_name != nullptr) X509_set_issuer_name(leaf, issuer_name);

    const EVP_MD* md = digest_for_key(sel->private_key);
    if (X509_sign(leaf, sel->private_key, md) == 0) { X509_free(leaf); return -1; }

    int total = 1 + static_cast<int>(sel->chain.size());
    auto** ders = static_cast<uint8_t**>(std::malloc(sizeof(uint8_t*) * total));
    auto* lens = static_cast<size_t*>(std::malloc(sizeof(size_t) * total));
    if (ders == nullptr || lens == nullptr) {
        if (ders) std::free(ders);
        if (lens) std::free(lens);
        X509_free(leaf); return -1;
    }
    for (int i = 0; i < total; ++i) { ders[i] = nullptr; lens[i] = 0; }
    auto encode = [](X509* c, uint8_t** out, size_t* out_len) -> bool {
        int n = i2d_X509(c, nullptr);
        if (n < 0) return false;
        *out = static_cast<uint8_t*>(std::malloc(static_cast<size_t>(n)));
        if (*out == nullptr) return false;
        uint8_t* pp = *out;
        if (i2d_X509(c, &pp) != n) { std::free(*out); *out = nullptr; return false; }
        *out_len = static_cast<size_t>(n);
        return true;
    };
    if (!encode(leaf, &ders[0], &lens[0])) {
        X509_free(leaf); std::free(ders); std::free(lens); return -1;
    }
    X509_free(leaf);
    for (size_t i = 0; i < sel->chain.size(); ++i) {
        if (!encode(sel->chain[i], &ders[i + 1], &lens[i + 1])) {
            for (size_t j = 0; j <= i; ++j) std::free(ders[j]);
            std::free(ders); std::free(lens); return -1;
        }
    }
    *out_ders = ders;
    *out_lens = lens;
    *out_count = total;
    return 0;
}

void ukeystore_free_chain(uint8_t** ders, size_t* lens, int count) {
    if (ders) {
        for (int i = 0; i < count; ++i) {
            if (ders[i]) std::free(ders[i]);
        }
        std::free(ders);
    }
    if (lens) std::free(lens);
}

void ukeystore_attest_free(uint8_t* ptr) { std::free(ptr); }

#ifdef UKEYSTORE_SELFTEST
int ukeystore_inspect_leaf(const uint8_t* leaf_der, size_t leaf_len,
                       int* vb_state, int* dev_locked,
                       uint8_t* vb_key, size_t* vb_key_len,
                       char* brand, size_t* brand_len,
                       char* model, size_t* model_len,
                       uint8_t* challenge, size_t* challenge_len) {
    using namespace ukeystore;
    const uint8_t* c = leaf_der;
    X509* leaf = d2i_X509(nullptr, &c, static_cast<long>(leaf_len));
    if (leaf == nullptr) return -1;
    ASN1_OBJECT* oid = OBJ_txt2obj(kAsn1TokenOid, 1);
    int idx = X509_get_ext_by_OBJ(leaf, oid, -1);
    ASN1_OBJECT_free(oid);
    if (idx < 0) { X509_free(leaf); return -2; }
    ASN1_OCTET_STRING* od = X509_EXTENSION_get_data(X509_get_ext(leaf, idx));
    const uint8_t* kc = od->data;
    KM_KEY_DESCRIPTION* kd = d2i_KM_KEY_DESCRIPTION(nullptr, &kc,
                                                    static_cast<long>(od->length));
    X509_free(leaf);
    if (kd == nullptr) return -3;
    KM_AUTH_LIST* tee = kd->tee_enforced;
    KM_ROOT_OF_TRUST* rot = tee ? tee->root_of_trust : nullptr;
    if (rot) {
        *vb_state = static_cast<int>(ASN1_ENUMERATED_get(rot->verified_boot_state));
        *dev_locked = rot->device_locked ? 1 : 0;
        int kl = ASN1_STRING_length(rot->verified_boot_key);
        if (kl > static_cast<int>(*vb_key_len)) kl = static_cast<int>(*vb_key_len);
        memcpy(vb_key, ASN1_STRING_get0_data(rot->verified_boot_key), kl);
        *vb_key_len = static_cast<size_t>(kl);
    } else { *vb_state = -1; *dev_locked = -1; *vb_key_len = 0; }
    auto cpstr = [](ASN1_OCTET_STRING* s, char* out, size_t* len) {
        if (!s) { *len = 0; return; }
        int l = ASN1_STRING_length(s);
        if (l > static_cast<int>(*len)) l = static_cast<int>(*len);
        memcpy(out, ASN1_STRING_get0_data(s), l); *len = static_cast<size_t>(l);
    };
    cpstr(tee ? tee->attestation_id_brand : nullptr, brand, brand_len);
    cpstr(tee ? tee->attestation_id_model : nullptr, model, model_len);
    cpstr(kd->attestation_challenge, reinterpret_cast<char*>(challenge), challenge_len);
    KM_KEY_DESCRIPTION_free(kd);
    return 0;
}
#endif

}
