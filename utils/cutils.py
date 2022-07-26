from hashlib import sha1, sha256, sha512
from Cryptodome.Cipher import AES, DES3
import hashlib
import hmac


def SHA1(data):
    sha = sha1()
    sha.update(data)
    return sha.hexdigest()


def SHA256(data):
    sha = sha256()
    sha.update(data)
    return sha.hexdigest()


def SHA512(data):
    sha = sha512()
    sha.update(data)
    return sha.hexdigest()


def HMAC_SHA1(key: bytes, msg: bytes):
    hmac_maker = hmac.new(key, msg, hashlib.sha1).hexdigest()
    return hmac_maker


def HMAC_SHA512(key: bytes, msg: bytes):
    hmac_maker = hmac.new(key, msg, hashlib.sha512).hexdigest()
    return hmac_maker


def HMAC_pkcs5_pbkdf2(password: bytes, salt: bytes, iteration: int, dklen: int, sizeHmac=64):
    count = 1
    out_key_len = dklen
    while dklen > 0:
        a_salt = salt + count.to_bytes(4, byteorder='big', signed=False)
        dl = bytes.fromhex(hmac.new(password, a_salt, hashlib.sha512).hexdigest())
        obuf = dl
        for index in range(1, iteration):
            dl = bytes.fromhex(hmac.new(password, dl, hashlib.sha512).hexdigest())
            obuf_tmp = b''
            for i in range(sizeHmac):
                obuf_tmp += (obuf[i] ^ dl[i]).to_bytes(1, byteorder='big', signed=False)
            obuf = obuf_tmp
            dl = obuf
        r = min(sizeHmac, out_key_len)
        dklen -= r
        count += 1
    assert len(obuf) >= out_key_len

    return obuf[:out_key_len].hex()


def DecryptAES_CBC(key: bytes, msg: bytes, iv: bytes):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    data = cipher.decrypt(msg)
    return data.hex()


def Decrypt_3DES_CBC(key: bytes, msg: bytes, iv: bytes):
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    data = cipher.decrypt(msg)
    return data

