// SPDX-License-Identifier: MIT
// Modified for the standalone ukeystore source distribution.

//! Native keystore2 attestation-chain extension.
//!
//! Disabled by default. Target selection is loaded once per process; profiles
//! and keyboxes are read for each attempted chain replacement. The generate
//! path requires a real KeyMint leaf and retains its public key. Stored-entry
//! certificate rewriting remains unimplemented and returns an error to the hook.
//!
//! See docs/integration.md before integrating.

use anyhow::{anyhow, Result};
use lazy_static::lazy_static;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::sync::RwLock;

use android_hardware_security_keymint::aidl::android::hardware::security::keymint::{
    Certificate::Certificate, KeyParameter::KeyParameter, KeyParameterValue::KeyParameterValue,
    Tag::Tag,
};
use packagemanager_aidl::aidl::android::content::pm::IPackageManagerNative::IPackageManagerNative;

const TARGET_CONF_PATH: &str = "/system/etc/security/ukeystore-attest-targets.conf";
const PROFILE_JSON_PATH: &str = "/system/etc/security/ukeystore-profile.json";
const KEYBOX_PATH: &str = "/system/etc/security/ukeystore-keybox.xml";
const KEYBOX_PATH_ROTATE: &str = "/data/misc/keystore/ukeystore-keybox.xml";

fn resolve_keybox_path() -> &'static str {
    if std::path::Path::new(KEYBOX_PATH_ROTATE).exists() {
        KEYBOX_PATH_ROTATE
    } else {
        KEYBOX_PATH
    }
}
const PACKAGE_NATIVE_SERVICE: &str = "package_native";

const DEFAULT_TARGETS: &[&str] = &[];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Skeleton,
    Real,
}

struct TargetConf {
    mode: Mode,
    target_uid_ranges: Vec<(u32, u32)>,
    target_uids: HashSet<u32>,
    target_packages: HashSet<String>,
}

lazy_static! {
    static ref TARGET_CONF: RwLock<TargetConf> = RwLock::new(load_target_conf());
    static ref UID_PKG_CACHE: RwLock<HashMap<u32, Vec<String>>> = RwLock::new(HashMap::new());
}

fn load_target_conf() -> TargetConf {
    let mut mode = Mode::Skeleton;
    let mut target_uid_ranges = Vec::new();
    let mut target_uids = HashSet::new();
    let mut target_packages = HashSet::new();
    match fs::read_to_string(TARGET_CONF_PATH) {
        Ok(contents) => {
            for line in contents.lines() {
                let line = line.split('#').next().unwrap_or("").trim();
                if line.is_empty() {
                    continue;
                }
                if let Some(rest) = line.strip_prefix("mode=") {
                    mode = match rest.trim() {
                        "real" => Mode::Real,
                        _ => Mode::Skeleton,
                    };
                    continue;
                }
                if let Some(rest) = line.strip_prefix("target_uids=") {
                    for uid_str in rest.split(',') {
                        if let Ok(uid) = uid_str.trim().parse::<u32>() {
                            target_uids.insert(uid);
                        }
                    }
                    continue;
                }
                if let Some(rest) = line.strip_prefix("target_uid_range=") {
                    if let Some((lo, hi)) = parse_uid_range(rest) {
                        target_uid_ranges.push((lo, hi));
                    } else {
                        log::warn!(
                            "[ukeystore] ignoring invalid target_uid_range={}",
                            rest.trim()
                        );
                    }
                    continue;
                }
                if let Some(rest) = line.strip_prefix("target_packages=") {
                    let pkg = rest.trim().to_string();
                    if !pkg.is_empty() {
                        target_packages.insert(pkg);
                    }
                    continue;
                }
                if let Ok(uid) = line.parse::<u32>() {
                    target_uids.insert(uid);
                    continue;
                }
                target_packages.insert(line.to_string());
            }
        }
        Err(_) => {
            for p in DEFAULT_TARGETS {
                target_packages.insert((*p).to_string());
            }
        }
    }
    log::info!(
        "[ukeystore] startup: mode={:?} target_uid_ranges={:?} target_uids={:?} target_packages={:?}",
        mode,
        target_uid_ranges,
        target_uids,
        target_packages
    );
    TargetConf {
        mode,
        target_uid_ranges,
        target_uids,
        target_packages,
    }
}

fn parse_uid_range(spec: &str) -> Option<(u32, u32)> {
    let (lo, hi) = spec.trim().split_once('-')?;
    let lo = lo.trim().parse::<u32>().ok()?;
    let hi = hi.trim().parse::<u32>().ok()?;
    (lo <= hi).then_some((lo, hi))
}

pub fn is_target_caller(caller_uid: u32) -> bool {
    log::info!("[ukeystore] hook entry: caller_uid={}", caller_uid);
    let conf = TARGET_CONF.read().unwrap();
    if conf.mode == Mode::Skeleton {
        return false;
    }
    if let Some(&(lo, hi)) = conf
        .target_uid_ranges
        .iter()
        .find(|&&(lo, hi)| caller_uid >= lo && caller_uid <= hi)
    {
        log::info!(
            "[ukeystore] is_target_caller uid={} matched range={}-{}",
            caller_uid,
            lo,
            hi
        );
        return true;
    }
    if conf.target_uids.contains(&caller_uid) {
        return true;
    }
    let target_packages = conf.target_packages.clone();
    drop(conf);
    if target_packages.is_empty() {
        return false;
    }
    match resolve_uid_to_packages(caller_uid) {
        Some(names) => {
            for name in &names {
                if !name.is_empty() && target_packages.contains(name) {
                    log::info!(
                        "[ukeystore] is_target_caller uid={} matched package={}",
                        caller_uid,
                        name
                    );
                    return true;
                }
            }
            false
        }
        None => false,
    }
}

fn resolve_uid_to_packages(uid: u32) -> Option<Vec<String>> {
    {
        let cache = UID_PKG_CACHE.read().unwrap();
        if let Some(pkgs) = cache.get(&uid) {
            return Some(pkgs.clone());
        }
    }
    let pm: binder::Strong<dyn IPackageManagerNative> =
        match binder::get_interface(PACKAGE_NATIVE_SERVICE) {
            Ok(p) => p,
            Err(e) => {
                log::debug!(
                    "[ukeystore] resolve_uid_to_packages: package_native unavailable: {:?}",
                    e
                );
                return None;
            }
        };
    let names = match pm.getNamesForUids(&[uid as i32]) {
        Ok(n) => n,
        Err(e) => {
            log::debug!(
                "[ukeystore] resolve_uid_to_packages: getNamesForUids({}) failed: {:?}",
                uid,
                e
            );
            return None;
        }
    };
    let mut cache = UID_PKG_CACHE.write().unwrap();
    cache.insert(uid, names.clone());
    Some(names)
}

pub fn challenge_present(params: &[KeyParameter]) -> bool {
    params.iter().any(|kp| kp.tag == Tag::ATTESTATION_CHALLENGE)
}

#[derive(Debug)]
pub struct SkeletonNotImplemented(pub &'static str);
impl std::fmt::Display for SkeletonNotImplemented {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "attestation_shim: {}", self.0)
    }
}
impl std::error::Error for SkeletonNotImplemented {}

mod ffi {
    use std::ffi::c_void;
    use std::os::raw::c_char;

    #[repr(C)]
    pub struct UkeystoreAttestParams {
        pub attestation_version: i32,
        pub attestation_security_level: i32,
        pub keymint_version: i32,
        pub keymint_security_level: i32,
        pub attestation_challenge: *const u8,
        pub attestation_challenge_len: usize,
        pub unique_id: *const u8,
        pub unique_id_len: usize,
        pub attestation_application_id: *const u8,
        pub attestation_application_id_len: usize,
        pub creation_datetime: i64,
        pub purpose: *const i64,
        pub purpose_count: usize,
        pub algorithm: i32,
        pub key_size: i32,
        pub digest: *const i64,
        pub digest_count: usize,
        pub padding: *const i64,
        pub padding_count: usize,
        pub ec_curve: i32,
        pub origin: i32,
        pub no_auth_required: i32,
        pub unlocked_device_required: i32,
        pub rollback_resistance: i32,
        pub verified_boot_key: *const u8,
        pub verified_boot_key_len: usize,
        pub device_locked: i32,
        pub verified_boot_state: i32,
        pub verified_boot_hash: *const u8,
        pub verified_boot_hash_len: usize,
        pub os_version: i32,
        pub os_patch_level: i32,
        pub vendor_patch_level: i32,
        pub boot_patch_level: i32,
        pub attestation_id_brand: *const u8,
        pub attestation_id_brand_len: usize,
        pub attestation_id_device: *const u8,
        pub attestation_id_device_len: usize,
        pub attestation_id_product: *const u8,
        pub attestation_id_product_len: usize,
        pub attestation_id_serial: *const u8,
        pub attestation_id_serial_len: usize,
        pub attestation_id_imei: *const u8,
        pub attestation_id_imei_len: usize,
        pub attestation_id_meid: *const u8,
        pub attestation_id_meid_len: usize,
        pub attestation_id_manufacturer: *const u8,
        pub attestation_id_manufacturer_len: usize,
        pub attestation_id_model: *const u8,
        pub attestation_id_model_len: usize,
        pub attestation_id_second_imei: *const u8,
        pub attestation_id_second_imei_len: usize,
    }

    #[allow(dead_code)]
    #[repr(C)]
    pub struct UkeystoreRotOverride {
        pub verified_boot_key: *const u8,
        pub verified_boot_key_len: usize,
        pub device_locked: i32,
        pub verified_boot_state: i32,
        pub verified_boot_hash: *const u8,
        pub verified_boot_hash_len: usize,
    }

    extern "C" {
        pub fn ukeystore_keybox_load(path: *const c_char, out_handle: *mut *mut c_void) -> i32;
        pub fn ukeystore_keybox_free(handle: *mut c_void);
        #[allow(dead_code)]
        pub fn ukeystore_hack_chain(
            handle: *mut c_void,
            algorithm_pref: *const c_char,
            genuine_leaf_der: *const u8,
            genuine_leaf_der_len: usize,
            rot: *const UkeystoreRotOverride,
            out_ders: *mut *mut *mut u8,
            out_lens: *mut *mut usize,
            out_count: *mut i32,
        ) -> i32;
        pub fn ukeystore_synth_chain(
            handle: *mut c_void,
            algorithm_pref: *const c_char,
            leaf_pubkey_der: *const u8,
            leaf_pubkey_der_len: usize,
            params: *const UkeystoreAttestParams,
            out_ders: *mut *mut *mut u8,
            out_lens: *mut *mut usize,
            out_count: *mut i32,
        ) -> i32;
        pub fn ukeystore_free_chain(ders: *mut *mut u8, lens: *mut usize, count: i32);
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
struct Profile {
    brand: String,
    device: String,
    product: String,
    manufacturer: String,
    model: String,
    os_version: i32,
    os_patch_level: i32,
    vendor_patch_level: i32,
    boot_patch_level: i32,
    verified_boot_key: Vec<u8>,
    verified_boot_hash: Vec<u8>,
}

fn json_extract(s: &str, key: &str) -> Option<String> {
    let pat = format!("\"{}\"", key);
    let idx = s.find(&pat)?;
    let after = &s[idx + pat.len()..];
    let colon = after.find(':')?;
    let rest = after[colon + 1..].trim_start();
    if let Some(after_quote) = rest.strip_prefix('"') {
        let close = after_quote.find('"')?;
        Some(after_quote[..close].to_string())
    } else {
        let end = rest
            .find(|c: char| c == ',' || c == '}' || c.is_whitespace())
            .unwrap_or(rest.len());
        Some(rest[..end].to_string())
    }
}

fn parse_hex(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() / 2);
    let chars: Vec<char> = s.chars().filter(|c| !c.is_whitespace()).collect();
    for chunk in chars.chunks(2) {
        if chunk.len() < 2 {
            break;
        }
        let hi = chunk[0].to_digit(16);
        let lo = chunk[1].to_digit(16);
        if let (Some(h), Some(l)) = (hi, lo) {
            out.push(((h << 4) | l) as u8);
        }
    }
    out
}

fn load_profile() -> Option<Profile> {
    let s = fs::read_to_string(PROFILE_JSON_PATH).ok()?;
    Some(Profile {
        brand: json_extract(&s, "brand").unwrap_or_default(),
        device: json_extract(&s, "device").unwrap_or_default(),
        product: json_extract(&s, "product").unwrap_or_default(),
        manufacturer: json_extract(&s, "manufacturer").unwrap_or_default(),
        model: json_extract(&s, "model").unwrap_or_default(),
        os_version: json_extract(&s, "os_version")
            .and_then(|x| x.parse().ok())
            .unwrap_or(0),
        os_patch_level: json_extract(&s, "os_patch_level")
            .and_then(|x| x.parse().ok())
            .unwrap_or(0),
        vendor_patch_level: json_extract(&s, "vendor_patch_level")
            .and_then(|x| x.parse().ok())
            .unwrap_or(0),
        boot_patch_level: json_extract(&s, "boot_patch_level")
            .and_then(|x| x.parse().ok())
            .unwrap_or(0),
        verified_boot_key: json_extract(&s, "verified_boot_key_hex")
            .map(|h| parse_hex(&h))
            .unwrap_or_default(),
        verified_boot_hash: json_extract(&s, "verified_boot_hash_hex")
            .map(|h| parse_hex(&h))
            .unwrap_or_default(),
    })
}

fn extract_spki_from_cert(cert_der: &[u8]) -> Result<Vec<u8>> {
    fn parse_tlv(s: &[u8], off: &mut usize) -> Result<(u8, usize, usize)> {
        if *off >= s.len() {
            return Err(anyhow!("DER eof"));
        }
        let tag = s[*off];
        *off += 1;
        if *off >= s.len() {
            return Err(anyhow!("DER eof2"));
        }
        let l0 = s[*off];
        *off += 1;
        let length = if l0 < 0x80 {
            l0 as usize
        } else {
            let n = (l0 & 0x7F) as usize;
            if n > 4 || *off + n > s.len() {
                return Err(anyhow!("DER bad len"));
            }
            let mut len = 0usize;
            for _ in 0..n {
                len = (len << 8) | s[*off] as usize;
                *off += 1;
            }
            len
        };
        let value_off = *off;
        *off += length;
        Ok((tag, value_off, length))
    }

    let mut off = 0usize;
    let (t1, v1, _l1) = parse_tlv(cert_der, &mut off)?;
    if t1 != 0x30 {
        return Err(anyhow!("expected SEQUENCE at outer"));
    }
    let mut cursor = v1;
    let (t2, v2, l2) = parse_tlv(cert_der, &mut cursor)?;
    if t2 != 0x30 {
        return Err(anyhow!("expected TBSCertificate SEQUENCE"));
    }
    let tbs_end = v2 + l2;
    let mut tbs_off = v2;
    let (t_v, _v_v, _l_v) = parse_tlv(cert_der, &mut tbs_off)?;
    if t_v != 0xA0 {
        tbs_off = v2;
    }
    let _ = parse_tlv(cert_der, &mut tbs_off)?;
    let _ = parse_tlv(cert_der, &mut tbs_off)?;
    let _ = parse_tlv(cert_der, &mut tbs_off)?;
    let _ = parse_tlv(cert_der, &mut tbs_off)?;
    let _ = parse_tlv(cert_der, &mut tbs_off)?;
    let spki_start = tbs_off;
    let _ = parse_tlv(cert_der, &mut tbs_off)?;
    if tbs_off > tbs_end {
        return Err(anyhow!("spki past TBS end"));
    }
    Ok(cert_der[spki_start..tbs_off].to_vec())
}

fn extract_blob(params: &[KeyParameter], tag: Tag) -> Option<&[u8]> {
    for kp in params {
        if kp.tag == tag {
            if let KeyParameterValue::Blob(ref b) = kp.value {
                return Some(b.as_slice());
            }
        }
    }
    None
}

#[allow(dead_code)]
fn extract_integer(params: &[KeyParameter], tag: Tag) -> Option<i32> {
    for kp in params {
        if kp.tag == tag {
            if let KeyParameterValue::Integer(n) = kp.value {
                return Some(n);
            }
        }
    }
    None
}

pub fn build_synth_chain(
    req_params: &[KeyParameter],
    existing_chain: &[Certificate],
) -> Result<Vec<Certificate>> {
    log::info!(
        "[ukeystore] chain rewrite entry: existing_chain_len={} keybox_path={}",
        existing_chain.len(),
        resolve_keybox_path()
    );
    let conf = TARGET_CONF.read().unwrap();
    if conf.mode == Mode::Skeleton {
        return Err(anyhow!(SkeletonNotImplemented(
            "mode=skeleton (default) — set mode=real in ukeystore-attest-targets.conf to enable"
        )));
    }
    drop(conf);

    if existing_chain.is_empty() {
        return Err(anyhow!(SkeletonNotImplemented(
            "no existing chain — KeyMint HAL returned an empty cert chain"
        )));
    }

    let leaf_der = existing_chain[0].encodedCertificate.as_slice();

    let spki = match extract_spki_from_cert(leaf_der) {
        Ok(s) => s,
        Err(e) => {
            log::debug!("[ukeystore] generate: SPKI extract from genuine leaf failed: {e}");
            return Err(anyhow!(SkeletonNotImplemented(
                "could not extract SPKI from genuine leaf — not a parseable X.509"
            )));
        }
    };

    let challenge = match extract_blob(req_params, Tag::ATTESTATION_CHALLENGE) {
        Some(c) => c,
        None => {
            return Err(anyhow!(SkeletonNotImplemented(
                "no ATTESTATION_CHALLENGE blob in params — cannot mint synthetic leaf"
            )));
        }
    };
    let empty_blob: &[u8] = &[];
    let app_id = extract_blob(req_params, Tag::ATTESTATION_APPLICATION_ID).unwrap_or(empty_blob);

    let profile = load_profile().unwrap_or_default();
    let vb_key = profile.verified_boot_key.clone();
    let vb_hash = profile.verified_boot_hash.clone();

    use std::ffi::CString;
    let keybox_path = CString::new(resolve_keybox_path()).unwrap();
    let mut handle: *mut std::ffi::c_void = std::ptr::null_mut();
    // SAFETY: `keybox_path` is a NUL-terminated CString owned in this scope; `handle`
    // is an out-pointer mutated only on rc == 0. `ukeystore_keybox_load` retains none of
    // these pointers past return.
    let rc = unsafe { ffi::ukeystore_keybox_load(keybox_path.as_ptr(), &mut handle as *mut _) };
    if rc != 0 || handle.is_null() {
        return Err(anyhow!(SkeletonNotImplemented(
            "keybox load failed — no ukeystore-keybox.xml at /data or /system, or unparseable"
        )));
    }

    let purpose: [i64; 2] = [2, 3];
    let digest: [i64; 1] = [4];

    let creation_datetime = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or(0);

    let params = ffi::UkeystoreAttestParams {
        attestation_version: 100,
        attestation_security_level: 1,
        keymint_version: 100,
        keymint_security_level: 1,
        attestation_challenge: challenge.as_ptr(),
        attestation_challenge_len: challenge.len(),
        unique_id: std::ptr::null(),
        unique_id_len: 0,
        attestation_application_id: app_id.as_ptr(),
        attestation_application_id_len: app_id.len(),
        creation_datetime,
        purpose: purpose.as_ptr(),
        purpose_count: purpose.len(),
        algorithm: 3,
        key_size: 256,
        digest: digest.as_ptr(),
        digest_count: digest.len(),
        padding: std::ptr::null(),
        padding_count: 0,
        ec_curve: 1,
        origin: 0,
        no_auth_required: 1,
        unlocked_device_required: 0,
        rollback_resistance: 0,
        verified_boot_key: vb_key.as_ptr(),
        verified_boot_key_len: vb_key.len(),
        device_locked: 1,
        verified_boot_state: 0,
        verified_boot_hash: vb_hash.as_ptr(),
        verified_boot_hash_len: vb_hash.len(),
        os_version: profile.os_version,
        os_patch_level: profile.os_patch_level,
        vendor_patch_level: profile.vendor_patch_level,
        boot_patch_level: profile.boot_patch_level,
        attestation_id_brand: profile.brand.as_ptr(),
        attestation_id_brand_len: profile.brand.len(),
        attestation_id_device: profile.device.as_ptr(),
        attestation_id_device_len: profile.device.len(),
        attestation_id_product: profile.product.as_ptr(),
        attestation_id_product_len: profile.product.len(),
        attestation_id_serial: std::ptr::null(),
        attestation_id_serial_len: 0,
        attestation_id_imei: std::ptr::null(),
        attestation_id_imei_len: 0,
        attestation_id_meid: std::ptr::null(),
        attestation_id_meid_len: 0,
        attestation_id_manufacturer: profile.manufacturer.as_ptr(),
        attestation_id_manufacturer_len: profile.manufacturer.len(),
        attestation_id_model: profile.model.as_ptr(),
        attestation_id_model_len: profile.model.len(),
        attestation_id_second_imei: std::ptr::null(),
        attestation_id_second_imei_len: 0,
    };

    log::info!(
        "[ukeystore] generate synth leaf: spki_len={} challenge_len={} appid_len={} brand={} model={} keybox={}",
        spki.len(),
        challenge.len(),
        app_id.len(),
        profile.brand,
        profile.model,
        resolve_keybox_path()
    );

    let alg_pref = CString::new("ecdsa").unwrap();
    let mut ders_ptr: *mut *mut u8 = std::ptr::null_mut();
    let mut lens_ptr: *mut usize = std::ptr::null_mut();
    let mut count: i32 = 0;
    // SAFETY: `handle` is valid (non-null, checked). `spki`, `challenge`, `app_id`,
    // `vb_key`, `vb_hash`, `purpose`, `digest`, `profile` (backing the id* byte
    // slices), `alg_pref` and `params` all remain live until after this call
    // (owned in this scope). Output pointers are mutated only on rc == 0.
    let rc = unsafe {
        ffi::ukeystore_synth_chain(
            handle,
            alg_pref.as_ptr(),
            spki.as_ptr(),
            spki.len(),
            &params as *const _,
            &mut ders_ptr,
            &mut lens_ptr,
            &mut count,
        )
    };
    if rc != 0 || count <= 0 {
        // SAFETY: `handle` is a valid pointer obtained from ukeystore_keybox_load above.
        unsafe { ffi::ukeystore_keybox_free(handle) };
        return Err(anyhow!(SkeletonNotImplemented(
            "ukeystore_synth_chain returned non-zero — keybox/profile issue or bad SPKI"
        )));
    }

    let mut chain = Vec::with_capacity(count as usize);
    for i in 0..(count as usize) {
        // SAFETY: `lens_ptr` and `ders_ptr` point to malloc'd arrays of size `count`
        // (postcondition of ukeystore_synth_chain on rc == 0). `i < count as usize` here.
        let len = unsafe { *lens_ptr.add(i) };
        // SAFETY: same as above; `ders_ptr.add(i)` is in-bounds for `i < count`.
        let der_ptr = unsafe { *ders_ptr.add(i) };
        let mut buf = vec![0u8; len];
        // SAFETY: `der_ptr` points to a malloc'd buffer of size `len` (postcondition of
        // ukeystore_synth_chain). `buf.as_mut_ptr()` is valid for `len` writes.
        unsafe { std::ptr::copy_nonoverlapping(der_ptr, buf.as_mut_ptr(), len) };
        chain.push(Certificate {
            encodedCertificate: buf,
        });
    }
    // SAFETY: `ders_ptr`/`lens_ptr` are malloc'd by ukeystore_synth_chain and must be freed
    // via the matching C-side ukeystore_free_chain (cannot use Rust's `free`).
    unsafe { ffi::ukeystore_free_chain(ders_ptr, lens_ptr, count) };
    // SAFETY: `handle` came from ukeystore_keybox_load and is still valid (not freed above
    // since count > 0 took the success path).
    unsafe { ffi::ukeystore_keybox_free(handle) };

    Ok(chain)
}

pub fn resign_chain(
    existing_cert: Option<&[u8]>,
    _existing_chain: Option<&[u8]>,
    _params: &[KeyParameter],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let conf = TARGET_CONF.read().unwrap();
    if conf.mode == Mode::Skeleton {
        return Err(anyhow!(SkeletonNotImplemented(
            "mode=skeleton — resign_chain disabled"
        )));
    }
    drop(conf);

    let _ = existing_cert;
    Err(anyhow!(SkeletonNotImplemented(
        "stored-certificate rewriting is not implemented"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_extract_string() {
        let s = r#"{"brand":"example","device":"sample","os_version":140000}"#;
        assert_eq!(json_extract(s, "brand").as_deref(), Some("example"));
        assert_eq!(json_extract(s, "device").as_deref(), Some("sample"));
        assert_eq!(json_extract(s, "os_version").as_deref(), Some("140000"));
    }

    #[test]
    fn hex_parse() {
        assert_eq!(parse_hex("deadbeef"), vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(parse_hex("DE AD BE EF"), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn tlv_walk_v3_cert() {
        assert!(extract_spki_from_cert(&[]).is_err());
        assert!(extract_spki_from_cert(&[0x00]).is_err());
    }
}
