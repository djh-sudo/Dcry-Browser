import cutils
import utils
import os
from FileFormat import *
import struct


def HandleMasterKey(mKey: DPAPI_MASTERKEY, raw_data: bytes, dwKeyLen: int):
    assert len(raw_data) == dwKeyLen + 32, "bad key file!"
    mKey.dwVersion = struct.unpack("<I", raw_data[0:4])[0]
    mKey.salt = raw_data[4:20].hex()
    mKey.rounds = struct.unpack("<I", raw_data[20:24])[0]
    mKey.algHash = struct.unpack("<I", raw_data[24:28])[0]
    mKey.algCrypt = struct.unpack("<I", raw_data[28:32])[0]
    mKey._dwKeyLen = dwKeyLen
    mKey.pbKey = raw_data[32:32 + dwKeyLen].hex()
    return mKey


def HandleCredentials(cred: DPAPI_MASTERKEY_CREDHIST, raw_data: bytes):
    assert len(raw_data) == 20, "bad credentials!"
    cred.dwVersion = struct.unpack("<I", raw_data[0:4])[0]
    cred.guid, cred._guid = utils.HandleGUID(cred.guid, raw_data[4:20])
    return cred


def HandleRawMasterkey(file_path):
    assert os.path.exists(file_path), "master key file not exists!"
    raw_file = utils.readFile(file_path)
    if len(raw_file) < 128:
        print('not a valid master file!')
        return None
    apapi_masterkey = DPAPI_MASTERKEYS()
    apapi_masterkey.dwVersion = struct.unpack("<I", raw_file[0:4])[0]
    apapi_masterkey.szGuid = raw_file[12:84].decode('utf-16')
    apapi_masterkey.dwFlags = struct.unpack("<I", raw_file[92:96])[0]
    apapi_masterkey.dwMasterKeyLen = struct.unpack("<Q", raw_file[96:104])[0]
    apapi_masterkey.dwBackupKeyLen = struct.unpack("<Q", raw_file[104:112])[0]
    apapi_masterkey.dwCreHistLen = struct.unpack("<Q", raw_file[112:120])[0]
    apapi_masterkey.dwDomainKeyLen = struct.unpack("<Q", raw_file[120:128])[0]
    # master key
    acc_len = apapi_masterkey.dwMasterKeyLen - 32
    apapi_masterkey.MasterKey = HandleMasterKey(apapi_masterkey.MasterKey, raw_file[128:160 + acc_len], acc_len)

    # backup key
    __dwKeyLen = apapi_masterkey.dwBackupKeyLen - 32
    apapi_masterkey.BackKey = HandleMasterKey(apapi_masterkey.BackKey,
                                              raw_file[160 + acc_len:192 + acc_len + __dwKeyLen], __dwKeyLen)
    acc_len += __dwKeyLen

    # credentials
    apapi_masterkey.CredHist = HandleCredentials(apapi_masterkey.CredHist, raw_file[192 + acc_len:212 + acc_len])

    # Domain Key
    # TODO
    return apapi_masterkey


def MemoryVerify(raw_masterkey: bytes, shaDerivedKey: bytes):
    flag = False
    salt = raw_masterkey[:16]
    saved_hash = raw_masterkey[16:64 + 16].hex()
    hmac1 = cutils.HMAC_SHA512(shaDerivedKey, salt)
    master_key = raw_masterkey[16 + 64:]
    hmac2 = cutils.HMAC_SHA512(bytes.fromhex(hmac1), master_key)
    if hmac2 == saved_hash:
        print('memory verify is OK!')
        flag = True
    return master_key.hex(), flag


def DecryptMasterKey(apapi_masterkey: DPAPI_MASTERKEYS, password: str, SID: str):
    assert apapi_masterkey, "no master key input"
    assert SID, "no SID input!"
    # step1
    wchar_password = utils.EncodeWCHAE(password).encode()
    pass_hash = cutils.SHA1(wchar_password)
    # step 2
    wchar_sid = (utils.EncodeWCHAE(SID) + '\0\0').encode()
    sha1DerivedKey = cutils.HMAC_SHA1(bytes.fromhex(pass_hash), wchar_sid)
    # step 3
    salt = apapi_masterkey.MasterKey.salt
    iteration = apapi_masterkey.MasterKey.rounds
    HMACHash = cutils.HMAC_pkcs5_pbkdf2(bytes.fromhex(sha1DerivedKey), bytes.fromhex(salt), iteration, 48)
    # step 4
    enc_pkey = apapi_masterkey.MasterKey.pbKey
    key = HMACHash[:64]
    IV = HMACHash[64:]
    plain_text = cutils.DecryptAES_CBC(bytes.fromhex(key), bytes.fromhex(enc_pkey), bytes.fromhex(IV))
    # step 5
    master_key, flag = MemoryVerify(bytes.fromhex(plain_text), bytes.fromhex(sha1DerivedKey))
    return master_key, flag
