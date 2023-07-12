import os
from typing import Tuple, Callable
import base64
from math import sqrt, ceil
import copy
import hashlib
import random

import pyasn1.codec.der.encoder
import pyasn1.type.univ

Key = Tuple[int, int]


def get_power_2_factors(n: int) -> (int, int):
    r = 0
    d = n
    while n > 0 and d % 2 == 0:
        d = d // 2
        r += 1
    return r, d


def miller_rabin_prime_test(n: int, k: int) -> bool:

    # Factor powers of 2 from n - 1 s.t. n - 1 = 2^r * d
    r, d = get_power_2_factors(n-1)

    for i in range(k):
        a = get_random_bits(n.bit_length())
        while a not in range(2, n-2+1):
            a = get_random_bits(n.bit_length())
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        n_1_found = False
        for j in range(r-1):
            x = pow(x, 2, n)
            if x == n - 1:
                n_1_found = True
                break
        if not n_1_found:
            return False
    return True


def get_random_bits(bit_length: int) -> int:
    return int.from_bytes(os.urandom((bit_length + 7) // 8), 'big')


def generate_prime_number(bit_length: int) -> int:

    # prime needs to be in range [2^(n-1), 2^n-1]
    low = pow(2, bit_length - 1)
    high = pow(2, bit_length) - 1

    while True:

        # Generate odd prime candidate in range
        candidate_prime = get_random_bits(bit_length)
        while candidate_prime not in range(low, high+1) or not candidate_prime % 2:
            candidate_prime = get_random_bits(bit_length)

        # with k rounds, miller rabin test gives false positive with probability (1/4)^k = 1/(2^2k)
        k = 64
        if miller_rabin_prime_test(candidate_prime, k):
            return candidate_prime


def extended_gcd(a, b):
    if not b:
        return 1, 0

    u, v = extended_gcd(b, a % b)
    return v, u - v * (a // b)


def calculate_private_key(e: int, p: int, q: int) -> int:
    u, _ = extended_gcd(e, (p-1)*(q-1))
    return u


## O restante é do github lá
def get_key_len(key: Key) -> int:
    '''Get the number of octets of the public/private key modulus'''
    _, n = key
    return n.bit_length() // 8


def os2ip(x: bytes) -> int:
    '''Converts an octet string to a nonnegative integer'''
    return int.from_bytes(x, byteorder='big')


def i2osp(x: int, xlen: int) -> bytes:
    '''Converts a nonnegative integer to an octet string of a specified length'''
    return x.to_bytes(xlen, byteorder='big')


def sha1(m: bytes) -> bytes:
    '''SHA-1 hash function'''
    hasher = hashlib.sha1()
    hasher.update(m)
    return hasher.digest()


def mgf1(seed: bytes, mlen: int, f_hash: Callable = sha1) -> bytes:
    '''MGF1 mask generation function with SHA-1'''
    t = b''
    hlen = len(f_hash(b''))
    for c in range(0, ceil(mlen / hlen)):
        _c = i2osp(c, 4)
        t += f_hash(seed + _c)
    return t[:mlen]


def xor(data: bytes, mask: bytes) -> bytes:
    '''Byte-by-byte XOR of two byte arrays'''
    masked = b''
    ldata = len(data)
    lmask = len(mask)
    for i in range(max(ldata, lmask)):
        if i < ldata and i < lmask:
            masked += (data[i] ^ mask[i]).to_bytes(1, byteorder='big')
        elif i < ldata:
            masked += data[i].to_bytes(1, byteorder='big')
        else:
            break
    return masked


def oaep_encode(m: bytes, k: int, label: bytes = b'',
                f_hash: Callable = sha1, f_mgf: Callable = mgf1) -> bytes:
    '''EME-OAEP encoding'''
    mlen = len(m)
    lhash = f_hash(label)
    hlen = len(lhash)
    ps = b'\x00' * (k - mlen - 2 * hlen - 2)
    db = lhash + ps + b'\x01' + m
    seed = os.urandom(hlen)
    db_mask = f_mgf(seed, k - hlen - 1, f_hash)
    masked_db = xor(db, db_mask)
    seed_mask = f_mgf(masked_db, hlen, f_hash)
    masked_seed = xor(seed, seed_mask)
    return b'\x00' + masked_seed + masked_db


def oaep_decode(c: bytes, k: int, label: bytes = b'',
                f_hash: Callable = sha1, f_mgf: Callable = mgf1) -> bytes:
    '''EME-OAEP decoding'''
    clen = len(c)
    lhash = f_hash(label)
    hlen = len(lhash)
    _, masked_seed, masked_db = c[:1], c[1:1 + hlen], c[1 + hlen:]
    seed_mask = f_mgf(masked_db, hlen, f_hash)
    seed = xor(masked_seed, seed_mask)
    db_mask = f_mgf(seed, k - hlen - 1, f_hash)
    db = xor(masked_db, db_mask)
    _lhash = db[:hlen]
    assert lhash == _lhash
    i = hlen
    while i < len(db):
        if db[i] == 0:
            i += 1
            continue
        elif db[i] == 1:
            i += 1
            break
        else:
            raise Exception()
    m = db[i:]
    return m


def encrypt(m: int, public_key: Key) -> int:
    '''Encrypt an integer using RSA public key'''
    e, n = public_key
    return pow(m, e, n)


def encrypt_raw(m: bytes, public_key: Key) -> bytes:
    '''Encrypt a byte array without padding'''
    k = get_key_len(public_key)
    c = encrypt(os2ip(m), public_key)
    return i2osp(c, k)


def encrypt_oaep(m: bytes, public_key: Key) -> bytes:
    '''Encrypt a byte array with OAEP padding'''
    hlen = 20  # SHA-1 hash length
    k = get_key_len(public_key)
    assert len(m) <= k - hlen - 2
    return encrypt_raw(oaep_encode(m, k), public_key)


def decrypt(c: int, private_key: Key) -> int:
    '''Decrypt an integer using RSA private key'''
    d, n = private_key
    return pow(c, d, n)


def decrypt_raw(c: bytes, private_key: Key) -> bytes:
    '''Decrypt a cipher byte array without padding'''
    k = get_key_len(private_key)
    m = decrypt(os2ip(c), private_key)
    return i2osp(m, k)


def decrypt_oaep(c: bytes, private_key: Key) -> bytes:
    '''Decrypt a cipher byte array with OAEP padding'''
    k = get_key_len(private_key)
    hlen = 20  # SHA-1 hash length
    assert len(c) == k
    assert k >= 2 * hlen + 2
    return oaep_decode(decrypt_raw(c, private_key), k)


if __name__ == "__main__":

    rsa_key_size = 2048
    prime_number_bit_length = rsa_key_size // 2

    # Generate prime numbers p and q
    p = generate_prime_number(prime_number_bit_length)
    q = generate_prime_number(prime_number_bit_length)

    # Calculate public key
    n = p * q
    e = 65537

    # Calculate private key
    d = calculate_private_key(e, p, q)

    pub_key, private_key = ((e, n), (d, n))

    # Encrypt
    plaintext = b'Cebola com Arr!!!oz com saco mucho'
    print("Mensagem Original:", plaintext, end="\n\n")

    cipher_text = encrypt_oaep('Cebola com Arr!!!oz com saco mucho'.encode('ascii'), pub_key)
    print("Cipher Text:", cipher_text, end="\n\n")

    # Decrypt
    recovered_plaintext = decrypt_oaep(cipher_text, private_key)
    print("Recovered Message:", recovered_plaintext, end="\n\n")

    assert (recovered_plaintext == plaintext)

"""    
((e, n), (d, n))
publica e privada
"""