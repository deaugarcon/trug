#!/usr/bin/env python3
"""
WP4 keybag cross-validation oracle (INDEPENDENT of Keybag.swift / FixtureBuilder).

Purpose: defeat the self-referential-fixture risk (Odb R1 / wp4.design.odb.md). This
script implements Apple's backup-keybag KEK derivation and RFC 3394 AES key-wrap from
the forensic references (richinfante / dunhamsteve / MVT / avibrazil / dinosec), using a
DIFFERENT crypto stack than the Swift code under test:
  - PBKDF2 via Python stdlib hashlib (not CommonCrypto)
  - AES-256-ECB block ops via OpenSSL libcrypto through ctypes (not CommonCrypto)

It emits a byte-exact synthetic backup keybag TLV plus the KNOWN-ANSWER class keys. The
Swift `Keybag` parser then unlocks that exact TLV and must recover the same class-key
bytes. Because the two implementations share no code, a derivation bug cannot hide.

CORRECTED derivation (wp4.design.odb.md, BINDING):
    temp = PBKDF2-HMAC-SHA256(password, DPSL, DPIC, dklen=32)   # INNER
    KEK  = PBKDF2-HMAC-SHA1 (temp,     SALT, ITER, dklen=32)    # OUTER

Usage:
    python3 Scripts/wp4-keybag-oracle.py emit   <out-dir>   # write fixture bytes + manifest
    python3 Scripts/wp4-keybag-oracle.py selftest           # wrap→unwrap round-trip, prints OK
"""
import ctypes
import ctypes.util
import hashlib
import json
import os
import struct
import sys

# ---- AES-256-ECB single-block via OpenSSL libcrypto (independent of CommonCrypto) ----

_lib = ctypes.CDLL(ctypes.util.find_library("crypto"))
_lib.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
_lib.EVP_aes_256_ecb.restype = ctypes.c_void_p


_lib.EVP_aes_256_cbc.restype = ctypes.c_void_p


def _aes256(cipher_fn, key: bytes, data: bytes, iv, encrypt: bool) -> bytes:
    """AES-256 with no library padding (caller does PKCS7). `iv` is None for ECB, 16B for CBC."""
    assert len(key) == 32 and len(data) % 16 == 0
    ctx = _lib.EVP_CIPHER_CTX_new()
    if not ctx:
        raise RuntimeError("EVP_CIPHER_CTX_new failed")
    try:
        cipher = cipher_fn()
        rc = _lib.EVP_CipherInit_ex(ctypes.c_void_p(ctx), ctypes.c_void_p(cipher),
                                    None, key, iv, 1 if encrypt else 0)
        if rc != 1:
            raise RuntimeError("EVP_CipherInit_ex failed")
        _lib.EVP_CIPHER_CTX_set_padding(ctypes.c_void_p(ctx), 0)
        out = ctypes.create_string_buffer(len(data) + 16)
        outlen = ctypes.c_int(0)
        rc = _lib.EVP_CipherUpdate(ctypes.c_void_p(ctx), out, ctypes.byref(outlen),
                                   data, len(data))
        if rc != 1:
            raise RuntimeError("EVP_CipherUpdate failed")
        total = outlen.value
        finlen = ctypes.c_int(0)
        rc = _lib.EVP_CipherFinal_ex(ctypes.c_void_p(ctx),
                                     ctypes.byref(out, total), ctypes.byref(finlen))
        if rc != 1:
            raise RuntimeError("EVP_CipherFinal_ex failed")
        total += finlen.value
        return out.raw[:total]
    finally:
        _lib.EVP_CIPHER_CTX_free(ctypes.c_void_p(ctx))


def _aes256_ecb(key: bytes, data: bytes, encrypt: bool) -> bytes:
    return _aes256(_lib.EVP_aes_256_ecb, key, data, None, encrypt)


def _aes256_cbc(key: bytes, data: bytes, iv: bytes, encrypt: bool) -> bytes:
    assert len(iv) == 16
    return _aes256(_lib.EVP_aes_256_cbc, key, data, iv, encrypt)


def pkcs7_pad(data: bytes, block: int = 16) -> bytes:
    pad = block - (len(data) % block)
    return data + bytes([pad]) * pad


# ---- RFC 3394 AES key wrap / unwrap (default IV 0xA6 x8) ----

_RFC3394_IV = b"\xA6" * 8


def aes_key_wrap(kek: bytes, plaintext: bytes) -> bytes:
    """RFC 3394 wrap. plaintext is n*8 bytes (n>=2). Returns (n+1)*8 bytes."""
    assert len(plaintext) % 8 == 0 and len(plaintext) >= 16
    n = len(plaintext) // 8
    R = [plaintext[i * 8:i * 8 + 8] for i in range(n)]
    A = _RFC3394_IV
    for j in range(6):
        for i in range(1, n + 1):
            B = _aes256_ecb(kek, A + R[i - 1], encrypt=True)
            t = (n * j) + i
            A = bytes(a ^ b for a, b in zip(B[:8], struct.pack(">Q", t)))
            R[i - 1] = B[8:]
    return A + b"".join(R)


def aes_key_unwrap(kek: bytes, ciphertext: bytes):
    """RFC 3394 unwrap. Returns plaintext on success, or None if integrity check fails."""
    assert len(ciphertext) % 8 == 0 and len(ciphertext) >= 24
    n = len(ciphertext) // 8 - 1
    A = ciphertext[:8]
    R = [ciphertext[8 + i * 8:8 + i * 8 + 8] for i in range(n)]
    for j in range(5, -1, -1):
        for i in range(n, 0, -1):
            t = (n * j) + i
            At = bytes(a ^ b for a, b in zip(A, struct.pack(">Q", t)))
            B = _aes256_ecb(kek, At + R[i - 1], encrypt=False)
            A = B[:8]
            R[i - 1] = B[8:]
    if A != _RFC3394_IV:
        return None
    return b"".join(R)


# ---- corrected KEK derivation ----

def derive_kek(password: bytes, dpsl: bytes, dpic: int, salt: bytes, iters: int) -> bytes:
    temp = hashlib.pbkdf2_hmac("sha256", password, dpsl, dpic, dklen=32)   # INNER
    return hashlib.pbkdf2_hmac("sha1", temp, salt, iters, dklen=32)        # OUTER


# ---- keybag TLV emission ----

WRAP_DEVICE = 1
WRAP_PASSCODE = 2


def _tlv(tag: bytes, payload: bytes) -> bytes:
    assert len(tag) == 4
    return tag + struct.pack(">L", len(payload)) + payload


def build_keybag_tlv(password: bytes, classes, version: int = 3) -> bytes:
    """
    classes: list of dicts {clas:int, wrap:int, key:32B}. Returns (tlv_bytes, wpky_by_clas).
    Deterministic salts/uuids so the fixture is byte-stable across runs.

    `version` is the VERS field; it defaults to 3 so the checked-in fixture stays byte-stable.
    Real iOS 27 (checkpoint C run 2) ships VERS 5 with the IDENTICAL wire format as 3/4, so a
    caller may emit a VERS-5 keybag without any other change for round-trip testing.
    """
    dpsl = bytes(range(20))                 # 20B deterministic
    salt = bytes(range(100, 120))           # 20B deterministic
    dpic = 10000
    iters = 10000
    kek = derive_kek(password, dpsl, dpic, salt, iters)

    out = bytearray()
    out += _tlv(b"VERS", struct.pack(">L", version))
    out += _tlv(b"TYPE", struct.pack(">L", 1))           # 1 = backup keybag
    out += _tlv(b"UUID", bytes(range(16)))               # keybag-level UUID
    out += _tlv(b"HMCK", bytes(range(40)))               # wrapped HMAC key (opaque to host)
    out += _tlv(b"SALT", salt)
    out += _tlv(b"ITER", struct.pack(">L", iters))
    out += _tlv(b"DPSL", dpsl)
    out += _tlv(b"DPIC", struct.pack(">L", dpic))

    wpky_by_clas = {}
    for idx, c in enumerate(classes):
        clas, wrap, key = c["clas"], c["wrap"], c["key"]
        # Per-class UUID leads the block (exercises the UUID-or-CLAS delimiter ambiguity, Q2).
        out += _tlv(b"UUID", bytes([idx]) * 16)
        out += _tlv(b"CLAS", struct.pack(">L", clas))
        out += _tlv(b"WRAP", struct.pack(">L", wrap))
        out += _tlv(b"KTYP", struct.pack(">L", 0))
        if wrap == WRAP_PASSCODE:
            wpky = aes_key_wrap(kek, key)                # 40B
            wpky_by_clas[clas] = wpky
        else:
            # Device-only class: WPKY the host cannot unwrap. Emit opaque 40B; host must SKIP it.
            wpky = bytes([0xDE]) * 40
        out += _tlv(b"WPKY", wpky)
    return bytes(out), wpky_by_clas


def fixture_classes():
    # Deterministic known class keys. One passcode class, one device-only class (R3).
    return [
        {"clas": 3, "wrap": WRAP_PASSCODE, "key": bytes((i * 7 + 1) & 0xFF for i in range(32))},
        {"clas": 4, "wrap": WRAP_PASSCODE, "key": bytes((i * 11 + 3) & 0xFF for i in range(32))},
        {"clas": 11, "wrap": WRAP_DEVICE, "key": bytes(32)},  # host cannot unwrap; must skip
    ]


PASSWORD = b"correct horse battery staple"

# Per-file encryption fixture (Task 11 decryptor oracle): a known plaintext encrypted under a
# random per-file key, that key RFC3394-wrapped under a passcode CLASS key (class 3), and the
# ciphertext produced with the fixed zero IV (wp4.design.odb.md A3). The Swift decryptor must
# recover KNOWN_PLAINTEXT from the wrapped key + ciphertext using the independently-derived class key.
# The plaintext is a real binary plist so `verify --level crypto`'s structural-signature check
# (bplist magic — padding success alone is insufficient, spec §4.2) has something to assert.
import plistlib  # noqa: E402
KNOWN_PLAINTEXT = plistlib.dumps({"known": "plaintext"}, fmt=plistlib.FMT_BINARY)
FILE_PROTECTION_CLASS = 3                                   # a passcode-wrapped class
FILE_KEY = bytes((i * 13 + 5) & 0xFF for i in range(32))    # deterministic per-file key
FILE_IV = b"\x00" * 16                                       # fixed zero IV (A3)


def build_encrypted_file(class_key: bytes):
    """Returns (encryption_key_blob_44B, ciphertext) for KNOWN_PLAINTEXT under FILE_KEY."""
    wrapped = aes_key_wrap(class_key, FILE_KEY)             # 40B
    assert len(wrapped) == 40
    enc_key = struct.pack(">L", len(wrapped)) + wrapped     # 4B length prefix + 40B = 44B (A4)
    ciphertext = _aes256_cbc(FILE_KEY, pkcs7_pad(KNOWN_PLAINTEXT), FILE_IV, encrypt=True)
    return enc_key, ciphertext


# Encrypted-Manifest.db material (task #10): real encrypted backups encrypt Manifest.db itself.
# Manifest.plist["ManifestKey"] = 4-byte protection-class prefix + RFC3394-wrapped manifest key
# (the SAME blob shape as a per-file EncryptionKey); Manifest.db is AES-256-CBC zero-IV under the
# unwrapped manifest key. ManifestKey is wrapped under a DIFFERENT passcode class (4) than the
# file (3), so the seam must consult the keybag, not hardcode a class.
#
# ENDIANNESS (Odb ManifestKey spot-check ruling, task #11): the 4-byte class prefix is
# LITTLE-ENDIAN ('<L') — iOSbackup ('<l') and dunhamsteve (LittleEndian.Uint32) agree, and it is
# the OPPOSITE of the keybag TLV's big-endian integers. A big-endian read of class 4 would yield
# 67108864 and select no key on a real backup.
MANIFEST_PROTECTION_CLASS = 4
MANIFEST_KEY = bytes((i * 17 + 9) & 0xFF for i in range(32))   # deterministic manifest key


def build_manifest_key_blob(class_key: bytes) -> bytes:
    """ManifestKey blob: 4B LITTLE-ENDIAN class prefix + RFC3394-wrapped manifest key (44B total)."""
    wrapped = aes_key_wrap(class_key, MANIFEST_KEY)        # 40B
    return struct.pack("<L", MANIFEST_PROTECTION_CLASS) + wrapped


def encrypt_manifest_db(plaintext_db: bytes) -> bytes:
    """AES-256-CBC zero-IV encrypt the (PKCS7-padded) Manifest.db bytes under MANIFEST_KEY."""
    return _aes256_cbc(MANIFEST_KEY, pkcs7_pad(plaintext_db), FILE_IV, encrypt=True)


def emit(out_dir: str):
    os.makedirs(out_dir, exist_ok=True)
    classes = fixture_classes()
    tlv, _ = build_keybag_tlv(PASSWORD, classes)
    with open(os.path.join(out_dir, "keybag.tlv"), "wb") as f:
        f.write(tlv)

    class_key = next(c["key"] for c in classes if c["clas"] == FILE_PROTECTION_CLASS)
    enc_key, ciphertext = build_encrypted_file(class_key)
    with open(os.path.join(out_dir, "encfile.ciphertext"), "wb") as f:
        f.write(ciphertext)
    with open(os.path.join(out_dir, "encfile.plaintext"), "wb") as f:
        f.write(KNOWN_PLAINTEXT)

    manifest_class_key = next(c["key"] for c in classes if c["clas"] == MANIFEST_PROTECTION_CLASS)
    manifest_key_blob = build_manifest_key_blob(manifest_class_key)

    known = {
        "password": PASSWORD.decode(),
        "passcode_classes": {
            str(c["clas"]): c["key"].hex()
            for c in classes if c["wrap"] == WRAP_PASSCODE
        },
        "device_only_classes": [c["clas"] for c in classes if c["wrap"] == WRAP_DEVICE],
        "tlv_sha256": hashlib.sha256(tlv).hexdigest(),
        "encrypted_file": {
            "domain": "HomeDomain",
            "relative_path": "known.txt",
            "protection_class": FILE_PROTECTION_CLASS,
            "encryption_key_blob_hex": enc_key.hex(),       # 44B: 4B prefix + 40B wrapped key
            "ciphertext_hex": ciphertext.hex(),
            "plaintext_hex": KNOWN_PLAINTEXT.hex(),          # binary plist (see encfile.plaintext)
            "plaintext_sha256": hashlib.sha256(KNOWN_PLAINTEXT).hexdigest(),
        },
        "encrypted_manifest": {
            "protection_class": MANIFEST_PROTECTION_CLASS,
            "manifest_key_blob_hex": manifest_key_blob.hex(),   # 44B: 4B class prefix + 40B wrapped
            "manifest_key_hex": MANIFEST_KEY.hex(),             # the unwrapped 32B key (FixtureBuilder encrypts with it)
        },
    }
    with open(os.path.join(out_dir, "keybag.known.json"), "w") as f:
        json.dump(known, f, indent=2, sort_keys=True)
    print(f"emitted {len(tlv)} TLV bytes; sha256={known['tlv_sha256']}")
    print(f"passcode classes: {sorted(int(k) for k in known['passcode_classes'])}")
    print(f"device-only (host-skipped) classes: {known['device_only_classes']}")
    print(f"encrypted file: class {FILE_PROTECTION_CLASS}, "
          f"{len(ciphertext)}B ciphertext, {len(KNOWN_PLAINTEXT)}B bplist plaintext")
    print(f"manifest key: class {MANIFEST_PROTECTION_CLASS}, {len(manifest_key_blob)}B ManifestKey blob")


def selftest():
    """Independent wrap→unwrap round-trip and a wrong-password rejection check."""
    classes = fixture_classes()
    tlv, wpky_by_clas = build_keybag_tlv(PASSWORD, classes)
    dpsl = bytes(range(20))
    salt = bytes(range(100, 120))
    kek = derive_kek(PASSWORD, dpsl, 10000, salt, 10000)
    for c in classes:
        if c["wrap"] != WRAP_PASSCODE:
            continue
        recovered = aes_key_unwrap(kek, wpky_by_clas[c["clas"]])
        assert recovered == c["key"], f"class {c['clas']} round-trip mismatch"
    wrong_kek = derive_kek(b"wrong password", dpsl, 10000, salt, 10000)
    bad = sum(1 for c in classes if c["wrap"] == WRAP_PASSCODE
              and aes_key_unwrap(wrong_kek, wpky_by_clas[c["clas"]]) is None)
    assert bad == len([c for c in classes if c["wrap"] == WRAP_PASSCODE]), "wrong pw must fail all"

    # Per-file decrypt round-trip: unwrap the file key with the class key, CBC-decrypt, strip PKCS7.
    class_key = next(c["key"] for c in classes if c["clas"] == FILE_PROTECTION_CLASS)
    enc_key, ciphertext = build_encrypted_file(class_key)
    wrapped_file_key = enc_key[4:]                              # strip 4B length prefix (A4)
    file_key = aes_key_unwrap(class_key, wrapped_file_key)
    assert file_key == FILE_KEY, "per-file key unwrap mismatch"
    padded = _aes256_cbc(file_key, ciphertext, FILE_IV, encrypt=False)
    plaintext = padded[:-padded[-1]]                           # strip PKCS7
    assert plaintext == KNOWN_PLAINTEXT, "file decrypt mismatch"

    # Manifest-key round-trip: unwrap the ManifestKey blob, encrypt+decrypt a sample manifest body.
    manifest_class_key = next(c["key"] for c in classes if c["clas"] == MANIFEST_PROTECTION_CLASS)
    blob = build_manifest_key_blob(manifest_class_key)
    # LITTLE-endian prefix (task #11): class 4 must serialize as 04 00 00 00, not 00 00 00 04.
    assert blob[:4] == bytes([MANIFEST_PROTECTION_CLASS, 0, 0, 0]), "ManifestKey LE class prefix bytes"
    assert struct.unpack("<L", blob[:4])[0] == MANIFEST_PROTECTION_CLASS, "ManifestKey class prefix (LE)"
    manifest_key = aes_key_unwrap(manifest_class_key, blob[4:])
    assert manifest_key == MANIFEST_KEY, "manifest key unwrap mismatch"
    sample = b"SQLite format 3\x00" + bytes(range(64))
    enc = encrypt_manifest_db(sample)
    dec = _aes256_cbc(manifest_key, enc, FILE_IV, encrypt=False)
    assert dec[:-dec[-1]] == sample, "manifest decrypt mismatch"
    print("selftest OK: corrected-order KEK wrap/unwrap round-trips; wrong password rejects all classes; "
          "per-file unwrap+CBC+PKCS7 recovers the known plaintext; ManifestKey unwrap + manifest "
          "CBC zero-IV round-trips")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "selftest"
    if cmd == "emit":
        emit(sys.argv[2] if len(sys.argv) > 2 else "Tests/Fixtures/wp4")
    elif cmd == "selftest":
        selftest()
    else:
        print(__doc__)
        sys.exit(2)
