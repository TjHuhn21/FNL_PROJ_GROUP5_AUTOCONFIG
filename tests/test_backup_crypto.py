"""Phase 3A: the .ncbak envelope (backup_crypto.py). Synthetic configurations and random
throwaway keys only; nothing is read from or written to the project."""
import hashlib
import json
import os
import struct
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import backup_crypto as C  # noqa: E402

CONFIG = (b'Building configuration...\r\n\r\nCurrent configuration : 99 bytes\r\n!\r\n'
          b'hostname SYNTH-SW1\r\n!\r\nusername admin secret 9 SynthHash-Not-Real\r\n!\r\nend\r\n')
KEY, OTHER = os.urandom(32), os.urandom(32)


def keys(**known):
    known = known or {'b1': KEY}

    def lookup(key_id):
        if key_id not in known:
            raise C.UnknownKey(f'Backup key {key_id} is not in this keyring.')
        return known[key_id]
    return lookup


def sealed(plaintext=CONFIG, key=KEY, key_id='b1', **meta):
    return C.encrypt_backup(plaintext, key, key_id, meta or {'host': '10.0.0.2',
                                                             'source': 'show running-config',
                                                             'privilege': 15})


def split(data):
    (length,) = struct.unpack('>I', data[6:10])
    return data[:10], data[10:10 + length], data[10 + length:]


def rebuild(header_bytes, body, prefix=None):
    prefix = prefix or (C.MAGIC + bytes([1]) + struct.pack('>I', len(header_bytes)))
    return prefix + header_bytes + body


# ---------------------------------------------------------------- round trips
@pytest.mark.parametrize('plaintext', [CONFIG, b'', b'x' * 70000, CONFIG.replace(b'\r\n', b'\n'),
                                       'hostname Ünïcode\nend\n'.encode('utf-8')],
                         ids=['crlf-config', 'empty', 'large', 'lf-config', 'unicode'])
def test_round_trip_returns_exactly_the_same_bytes(plaintext):
    data = sealed(plaintext)
    out, header = C.decrypt_backup(data, keys())
    assert out == plaintext
    assert header['plaintext_sha256'] == hashlib.sha256(plaintext).hexdigest()
    assert header['plaintext_size'] == len(plaintext)
    assert header['alg'] == 'AES-256-GCM' and header['key_id'] == 'b1'
    assert header['host'] == '10.0.0.2' and header['privilege'] == 15


def test_the_file_is_not_readable_without_the_key():
    data = sealed()
    assert b'hostname' not in data and b'SynthHash' not in data and CONFIG not in data
    assert data.startswith(b'NCBAK\x01')


def test_every_encryption_uses_a_fresh_nonce():
    nonces = {C.read_backup_header(sealed())[0]['nonce'] for _ in range(50)}
    assert len(nonces) == 50
    assert all(len(C._unb64(n, 12, 'nonce')) == 12 for n in nonces)


def test_the_aad_is_the_exact_byte_range_of_the_file():
    data = sealed()
    header, aad, ciphertext = C.read_backup_header(data)
    prefix, header_bytes, body = split(data)
    assert aad == prefix + header_bytes and ciphertext == body


def test_a_header_with_the_same_meaning_but_other_bytes_fails():
    """Authentication covers the ORIGINAL header bytes: re-serialising it (other spacing,
    key order) is a change, even though the JSON means the same."""
    prefix, header_bytes, body = split(sealed())
    pretty = json.dumps(json.loads(header_bytes), indent=1, sort_keys=False).encode('ascii')
    with pytest.raises(C.AuthenticationFailed):
        C.decrypt_backup(rebuild(pretty, body), keys())


# ---------------------------------------------------------------- keys
def test_the_wrong_key_is_refused():
    with pytest.raises(C.AuthenticationFailed) as err:
        C.decrypt_backup(sealed(), keys(b1=OTHER))
    assert str(err.value) == C.AUTH_FAILED


def test_an_unknown_key_id_is_refused():
    with pytest.raises(C.UnknownKey):
        C.decrypt_backup(sealed(key_id='b7'), keys())


@pytest.mark.parametrize('key', [b'', b'short', os.urandom(16), os.urandom(33), 'text' * 8, None])
def test_only_32_byte_keys_are_accepted(key):
    with pytest.raises(C.BackupCryptoError):
        C.encrypt_backup(CONFIG, key, 'b1')


@pytest.mark.parametrize('key_id', ['', 'b0', 'k1', 'B1', 'b1 ', 'b01', '../b1', 'b1234567', 1])
def test_key_ids_are_validated(key_id):
    with pytest.raises(C.BackupCryptoError):
        C.encrypt_backup(CONFIG, KEY, key_id)


def test_fingerprints_identify_keys_without_revealing_them():
    fp = C.fingerprint(KEY)
    assert C.valid_fingerprint(fp) and fp == C.fingerprint(KEY) != C.fingerprint(OTHER)
    assert KEY.hex() not in fp and fp not in KEY.hex()


# ---------------------------------------------------------------- tampering
@pytest.mark.parametrize('field, value', [
    ('host', '10.0.0.3'), ('created_utc', '2020-01-01T00:00:00.000000Z'), ('privilege', 1),
    ('source', 'something else'), ('key_id', 'b2'),
])
def test_changing_any_header_field_breaks_authentication(field, value):
    prefix, header_bytes, body = split(sealed())
    header = json.loads(header_bytes)
    header[field] = value
    changed = json.dumps(header, sort_keys=True, separators=(',', ':')).encode('ascii')
    with pytest.raises((C.AuthenticationFailed, C.UnknownKey)):
        C.decrypt_backup(rebuild(changed, body), keys(b1=KEY, b2=KEY))


def test_changing_the_recorded_hash_or_size_is_refused():
    prefix, header_bytes, body = split(sealed())
    header = json.loads(header_bytes)
    header['plaintext_sha256'] = '0' * 64
    changed = json.dumps(header, sort_keys=True, separators=(',', ':')).encode('ascii')
    with pytest.raises(C.AuthenticationFailed):
        C.decrypt_backup(rebuild(changed, body), keys())
    header = json.loads(header_bytes)
    header['plaintext_size'] += 1
    changed = json.dumps(header, sort_keys=True, separators=(',', ':')).encode('ascii')
    with pytest.raises(C.FormatError):                    # length no longer matches
        C.decrypt_backup(rebuild(changed, body), keys())


@pytest.mark.parametrize('where', ['first ciphertext byte', 'middle', 'last tag byte',
                                   'first tag byte'])
def test_changing_the_ciphertext_or_tag_is_refused(where):
    data = bytearray(sealed())
    _, header_bytes, body = split(bytes(data))
    start = 10 + len(header_bytes)
    index = {'first ciphertext byte': start, 'middle': start + len(body) // 2,
             'last tag byte': len(data) - 1, 'first tag byte': len(data) - 16}[where]
    data[index] ^= 0x01
    with pytest.raises(C.AuthenticationFailed):
        C.decrypt_backup(bytes(data), keys())


def test_changing_the_nonce_is_refused():
    prefix, header_bytes, body = split(sealed())
    header = json.loads(header_bytes)
    header['nonce'] = C._b64(os.urandom(12))
    changed = json.dumps(header, sort_keys=True, separators=(',', ':')).encode('ascii')
    with pytest.raises(C.AuthenticationFailed):
        C.decrypt_backup(rebuild(changed, body), keys())


def test_a_correct_tag_on_a_wrong_hash_is_an_integrity_error(monkeypatch):
    """If the recorded hash ever disagreed with the authenticated plaintext (a bug in a
    writer), decryption still refuses it."""
    real = C.hashlib.sha256

    def writer_bug(data=b''):
        return real(data + b'!')
    monkeypatch.setattr(C.hashlib, 'sha256', writer_bug)
    data = sealed()
    monkeypatch.setattr(C.hashlib, 'sha256', real)
    with pytest.raises(C.IntegrityError):
        C.decrypt_backup(data, keys())


# ---------------------------------------------------------------- structure
def test_truncated_files_are_refused():
    data = sealed()
    for cut in (0, 3, 5, 9, 10, 40, len(data) - 17, len(data) - 1):
        with pytest.raises(C.FormatError):
            C.decrypt_backup(data[:cut], keys())


def test_extra_bytes_are_refused():
    with pytest.raises(C.FormatError):
        C.decrypt_backup(sealed() + b'\x00', keys())


@pytest.mark.parametrize('prefix', [b'NCBAX\x01', b'ncbak\x01', b'NCRCV\x01', b'\x00\x00\x00\x00\x00\x01'])
def test_a_wrong_signature_is_refused(prefix):
    data = sealed()
    with pytest.raises(C.FormatError):
        C.decrypt_backup(prefix + data[6:], keys())


@pytest.mark.parametrize('version', [0, 2, 255])
def test_unsupported_versions_are_refused(version):
    data = bytearray(sealed())
    data[5] = version
    with pytest.raises(C.UnsupportedVersion):
        C.decrypt_backup(bytes(data), keys())


def test_oversized_headers_and_files_are_refused():
    data = sealed()
    big = C.MAGIC + bytes([1]) + struct.pack('>I', C.MAX_HEADER_BYTES + 1) + data[10:]
    with pytest.raises(C.FormatError):
        C.decrypt_backup(big, keys())
    zero = C.MAGIC + bytes([1]) + struct.pack('>I', 0) + data[10:]
    with pytest.raises(C.FormatError):
        C.decrypt_backup(zero, keys())
    with pytest.raises(C.FormatError):
        C.read_backup_header(b'NCBAK\x01' + b'\x00' * (C.MAX_FILE_BYTES))
    with pytest.raises(C.BackupCryptoError):
        C.encrypt_backup(b'x' * (C.MAX_PLAINTEXT_BYTES + 1), KEY, 'b1')


@pytest.mark.parametrize('mutate', [
    lambda h: h.pop('alg'), lambda h: h.update(alg='AES-128-CBC'), lambda h: h.pop('nonce'),
    lambda h: h.update(nonce=C._b64(os.urandom(8))), lambda h: h.update(nonce='not base64!'),
    lambda h: h.update(plaintext_sha256='XYZ'), lambda h: h.update(plaintext_size='99'),
    lambda h: h.update(plaintext_size=True), lambda h: h.update(format='other'),
    lambda h: h.update(key_id='zz'), lambda h: h.update(privilege='15'),
])
def test_malformed_headers_are_refused_before_decryption(mutate):
    prefix, header_bytes, body = split(sealed())
    header = json.loads(header_bytes)
    mutate(header)
    changed = json.dumps(header, sort_keys=True, separators=(',', ':')).encode('ascii')
    with pytest.raises(C.FormatError):
        C.read_backup_header(rebuild(changed, body))


@pytest.mark.parametrize('raw', [b'[1,2,3]', b'not json', b'{"alg":"a","alg":"b"}', b'\xff\xfe'])
def test_non_json_lists_and_duplicate_fields_are_refused(raw):
    with pytest.raises(C.FormatError):
        C.read_backup_header(rebuild(raw, b'\x00' * 16))


@pytest.mark.parametrize('raw', [b'[' * 4000, b'{"a":' * 800 + b'1' + b'}' * 800,
                                 b'[' * 2000 + b']' * 2000],
                         ids=['open-arrays', 'nested-objects', 'balanced-arrays'])
def test_deeply_nested_headers_are_refused_cleanly(raw):
    """A 4 KiB header can nest thousands of levels: a FormatError, never RecursionError."""
    data = rebuild(raw, b'\x00' * 16)
    with pytest.raises(C.FormatError):
        C.read_backup_header(data)
    with pytest.raises(C.FormatError):
        C.decrypt_backup(data, keys())


def test_running_out_of_memory_while_parsing_is_a_format_error(monkeypatch):
    data = sealed()

    def no_memory(*a, **k):
        raise MemoryError
    monkeypatch.setattr(C.json, 'loads', no_memory)
    with pytest.raises(C.FormatError):
        C.read_backup_header(data)


def test_metadata_is_limited_to_known_non_secret_fields():
    for bad in ({'password': 'x'}, {'host': 5}, {'privilege': '15'}, {'host': 'a\nb'},
                {'host': 'x' * 201}, {'privilege': True}):
        with pytest.raises(C.BackupCryptoError):
            C.encrypt_backup(CONFIG, KEY, 'b1', bad)


def test_errors_never_contain_keys_or_configuration():
    messages = []
    for call in (lambda: C.decrypt_backup(sealed(), keys(b1=OTHER)),
                 lambda: C.decrypt_backup(sealed()[:20], keys()),
                 lambda: C.decrypt_backup(sealed(key_id='b9'), keys()),
                 lambda: C.encrypt_backup(CONFIG, b'short', 'b1')):
        with pytest.raises(C.BackupCryptoError) as err:
            call()
        messages.append(str(err.value))
    text = ' '.join(messages)
    for secret in (KEY.hex(), OTHER.hex(), C._b64(KEY), 'SynthHash', 'SYNTH-SW1'):
        assert secret not in text
