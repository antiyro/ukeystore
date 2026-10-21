// SPDX-License-Identifier: MIT
// Host-only tests. All signing keys are generated at runtime in a temporary folder.
#define UKEYSTORE_SELFTEST
#define UKEYSTORE_COMPAT_PBKDF2
#include "../src/attest_ext.cpp"
#include "../compat/legacy_crypto.cpp"

#include <array>
#include <cassert>
#include <fstream>
#include <iostream>

static EVP_PKEY* new_key() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    assert(ctx);
    assert(EVP_PKEY_keygen_init(ctx) > 0);
    assert(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) > 0);
    EVP_PKEY* key = nullptr;
    assert(EVP_PKEY_keygen(ctx, &key) > 0);
    EVP_PKEY_CTX_free(ctx);
    return key;
}

static X509* signing_cert(EVP_PKEY* key) {
    X509* cert = X509_new();
    assert(cert);
    assert(X509_set_version(cert, 2));
    assert(ASN1_INTEGER_set(X509_get_serialNumber(cert), 1));
    assert(X509_gmtime_adj(X509_getm_notBefore(cert), -60));
    assert(X509_gmtime_adj(X509_getm_notAfter(cert), 86400));
    X509_NAME* name = X509_get_subject_name(cert);
    assert(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        reinterpret_cast<const uint8_t*>("Ephemeral Test Signer"), -1, -1, 0));
    assert(X509_set_issuer_name(cert, name));
    assert(X509_set_pubkey(cert, key));
    assert(X509_sign(cert, key, EVP_sha256()) > 0);
    return cert;
}

static std::string pem_key(EVP_PKEY* key) {
    BIO* bio = BIO_new(BIO_s_mem());
    assert(bio);
    assert(PEM_write_bio_PrivateKey(bio, key, nullptr, nullptr, 0, nullptr, nullptr));
    char* data = nullptr;
    long size = BIO_get_mem_data(bio, &data);
    std::string value(data, static_cast<size_t>(size));
    BIO_free(bio);
    return value;
}

static std::string pem_cert(X509* cert) {
    BIO* bio = BIO_new(BIO_s_mem());
    assert(bio);
    assert(PEM_write_bio_X509(bio, cert));
    char* data = nullptr;
    long size = BIO_get_mem_data(bio, &data);
    std::string value(data, static_cast<size_t>(size));
    BIO_free(bio);
    return value;
}

static ukeystore::KM_KEY_DESCRIPTION* description(X509* cert) {
    ASN1_OBJECT* oid = OBJ_txt2obj("1.3.6.1.4.1.11129.2.1.17", 1);
    assert(oid);
    int index = X509_get_ext_by_OBJ(cert, oid, -1);
    ASN1_OBJECT_free(oid);
    assert(index >= 0);
    ASN1_OCTET_STRING* data = X509_EXTENSION_get_data(X509_get_ext(cert, index));
    const uint8_t* cursor = ASN1_STRING_get0_data(data);
    auto* record = ukeystore::d2i_KM_KEY_DESCRIPTION(
        nullptr, &cursor, ASN1_STRING_length(data));
    assert(record);
    return record;
}

static void check_bytes(ASN1_OCTET_STRING* actual, const uint8_t* expected, size_t size) {
    assert(actual);
    assert(ASN1_STRING_length(actual) == static_cast<int>(size));
    assert(std::memcmp(ASN1_STRING_get0_data(actual), expected, size) == 0);
}

int main(int argc, char** argv) {
    assert(argc == 2);
    std::string folder = argv[1];
    std::string xml_path = folder + "/ephemeral.xml";
    std::string invalid_path = folder + "/invalid.xml";
    std::ofstream(invalid_path) << "<invalid/>";
    void* handle = nullptr;
    assert(ukeystore_keybox_load(invalid_path.c_str(), &handle) != 0);
    assert(ukeystore_keybox_load(nullptr, &handle) != 0);

    EVP_PKEY* signer = new_key();
    EVP_PKEY* app = new_key();
    X509* signer_cert = signing_cert(signer);
    {
        std::ofstream xml(xml_path);
        assert(xml);
        xml << "<AndroidAttestation><NumberOfKeyboxes>1</NumberOfKeyboxes>"
               "<Keybox DeviceID=\"ephemeral\"><Key algorithm=\"ecdsa\">"
               "<PrivateKey format=\"pem\">" << pem_key(signer) << "</PrivateKey>"
               "<CertificateChain><NumberOfCertificates>1</NumberOfCertificates>"
               "<Certificate format=\"pem\">" << pem_cert(signer_cert) << "</Certificate>"
               "</CertificateChain></Key></Keybox></AndroidAttestation>";
    }
    assert(ukeystore_keybox_load(xml_path.c_str(), &handle) == 0);
    assert(handle);
    assert(ukeystore_keybox_entry_count(handle) == 1);
    assert(ukeystore_keybox_chain_count(handle, 0) == 1);

    std::array<uint8_t, 32> boot_key{}, boot_hash{};
    boot_key.fill(0x12);
    boot_hash.fill(0x34);
    const uint8_t challenge[] = {0x00, 0x01, 0xff, 0x00, 0x42};
    const uint8_t app_id[] = {0x30, 0x03, 0x04, 0x01, 0x00};
    const int64_t purpose[] = {2, 3};
    const int64_t digest[] = {4};
    UkeystoreAttestParams params{};
    params.attestation_version = 100;
    params.attestation_security_level = 1;
    params.keymint_version = 100;
    params.keymint_security_level = 1;
    params.attestation_challenge = challenge;
    params.attestation_challenge_len = sizeof(challenge);
    params.attestation_application_id = app_id;
    params.attestation_application_id_len = sizeof(app_id);
    params.purpose = purpose;
    params.purpose_count = 2;
    params.algorithm = 3;
    params.key_size = 256;
    params.digest = digest;
    params.digest_count = 1;
    params.ec_curve = 1;
    params.no_auth_required = 1;
    params.verified_boot_key = boot_key.data();
    params.verified_boot_key_len = boot_key.size();
    params.verified_boot_hash = boot_hash.data();
    params.verified_boot_hash_len = boot_hash.size();
    params.device_locked = 1;
    params.verified_boot_state = 0;
    const uint8_t brand[] = "example";
    params.attestation_id_brand = brand;
    params.attestation_id_brand_len = sizeof(brand) - 1;

    uint8_t* raw = nullptr;
    size_t raw_len = 0;
    assert(ukeystore_build_attest_record(&params, &raw, &raw_len) == 0);
    uint8_t* roundtrip = nullptr;
    size_t roundtrip_len = 0;
    assert(ukeystore_roundtrip_attest_record(raw, raw_len, &roundtrip, &roundtrip_len) == 0);
    assert(raw_len == roundtrip_len);
    assert(std::memcmp(raw, roundtrip, raw_len) == 0);
    ukeystore_attest_free(raw);
    ukeystore_attest_free(roundtrip);
    const uint8_t invalid_der[] = {0x30, 0x80, 0x00};
    assert(ukeystore_roundtrip_attest_record(invalid_der, sizeof(invalid_der),
                                           &roundtrip, &roundtrip_len) != 0);

    int spki_len = i2d_PUBKEY(app, nullptr);
    assert(spki_len > 0);
    std::vector<uint8_t> spki(static_cast<size_t>(spki_len));
    uint8_t* spki_cursor = spki.data();
    assert(i2d_PUBKEY(app, &spki_cursor) == spki_len);
    uint8_t** chain = nullptr;
    size_t* lengths = nullptr;
    int count = 0;
    assert(ukeystore_synth_chain(handle, "ecdsa", spki.data(), spki.size(), &params,
                                &chain, &lengths, &count) == 0);
    assert(count == 2);
    const uint8_t* cursor = chain[0];
    X509* leaf = d2i_X509(nullptr, &cursor, static_cast<long>(lengths[0]));
    assert(leaf);
    assert(X509_verify(leaf, signer) == 1);
    EVP_PKEY* actual_key = X509_get_pubkey(leaf);
    assert(actual_key);
    assert(EVP_PKEY_eq(actual_key, app) == 1);
    EVP_PKEY_free(actual_key);
    assert(X509_NAME_cmp(X509_get_issuer_name(leaf), X509_get_subject_name(signer_cert)) == 0);
    auto* record = description(leaf);
    check_bytes(record->attestation_challenge, challenge, sizeof(challenge));
    check_bytes(record->software_enforced->attestation_application_id, app_id, sizeof(app_id));
    check_bytes(record->tee_enforced->attestation_id_brand, brand, sizeof(brand) - 1);
    check_bytes(record->tee_enforced->root_of_trust->verified_boot_key,
                boot_key.data(), boot_key.size());
    ukeystore::KM_KEY_DESCRIPTION_free(record);

    // The preservation helper must retain challenge/public key while replacing RoT.
    boot_key.fill(0x56);
    UkeystoreRotOverride rot{boot_key.data(), boot_key.size(), 0, 2,
                             boot_hash.data(), boot_hash.size()};
    uint8_t** preserved = nullptr;
    size_t* preserved_lengths = nullptr;
    int preserved_count = 0;
    assert(ukeystore_hack_chain(handle, "ecdsa", chain[0], lengths[0], &rot,
                               &preserved, &preserved_lengths, &preserved_count) == 0);
    assert(preserved_count == 2);
    cursor = preserved[0];
    X509* updated = d2i_X509(nullptr, &cursor, static_cast<long>(preserved_lengths[0]));
    assert(updated && X509_verify(updated, signer) == 1);
    record = description(updated);
    check_bytes(record->attestation_challenge, challenge, sizeof(challenge));
    check_bytes(record->tee_enforced->attestation_id_brand, brand, sizeof(brand) - 1);
    check_bytes(record->tee_enforced->root_of_trust->verified_boot_key,
                boot_key.data(), boot_key.size());
    assert(ASN1_ENUMERATED_get(record->tee_enforced->root_of_trust->verified_boot_state) == 2);
    assert(record->tee_enforced->root_of_trust->device_locked == 0);
    ukeystore::KM_KEY_DESCRIPTION_free(record);
    X509_free(updated);
    X509_free(leaf);
    ukeystore_free_chain(preserved, preserved_lengths, preserved_count);
    ukeystore_free_chain(chain, lengths, count);
    ukeystore_keybox_free(handle);

    std::array<uint8_t, 16> salt{};
    for (size_t size : {16u, 32u}) {
        std::vector<uint8_t> expected(size), actual(size);
        assert(PKCS5_PBKDF2_HMAC("test", 4, salt.data(), 16, 8192,
            size == 16 ? EVP_sha1() : EVP_sha256(), static_cast<int>(size), expected.data()));
        PBKDF2(actual.data(), size, "test", 4, salt.data());
        assert(actual == expected);
    }
    X509_free(signer_cert);
    EVP_PKEY_free(signer);
    EVP_PKEY_free(app);
    std::cout << "PASS: XML rejection, DER roundtrip, generated/preserved chains, "
                 "signatures, request binding and PBKDF2 adapter\n";
}
