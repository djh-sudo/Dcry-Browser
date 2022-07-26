import os
import datetime as dt
import struct
import cutils
import utils
from FileFormat import *


def HandleBlob(blob: DPAPI_BLOB, raw_data: bytes):
    blob.dwVersion = struct.unpack("<I", raw_data[0:4])[0]
    blob.guidProvider, blob._guidProvider = utils.HandleGUID(blob.guidProvider, raw_data[4:20])
    blob.dwMasterKeyVersion = struct.unpack("<I", raw_data[20:24])[0]
    blob.guidMasterKey, blob._guidMasterKey = utils.HandleGUID(blob.guidMasterKey, raw_data[24:40])
    blob.dwFlags = struct.unpack("<I", raw_data[40:44])[0]
    blob.dwDescriptionLen = struct.unpack("<I", raw_data[44:48])[0]

    acc_len = blob.dwDescriptionLen
    blob.szDescription = raw_data[48:48 + blob.dwDescriptionLen].decode('utf-16').replace('\r\n\0', '')

    blob.algCrypt = struct.unpack("<I", raw_data[48 + acc_len:52 + acc_len])[0]
    blob.dwAlgCryptLen = struct.unpack("<I", raw_data[52 + acc_len:56 + acc_len])[0]

    blob.dwSaltLen = struct.unpack("<I", raw_data[56 + acc_len:60 + acc_len])[0]
    blob.pbSalt = raw_data[60 + acc_len:60 + acc_len + blob.dwSaltLen].hex()
    acc_len += blob.dwSaltLen

    blob.dwHmacKeyLen = struct.unpack("<I", raw_data[60 + acc_len:64 + acc_len])[0]
    blob.pbHmackKey = raw_data[64 + acc_len:64 + acc_len + blob.dwHmacKeyLen].hex()
    acc_len += blob.dwHmacKeyLen

    blob.algHash = struct.unpack("<I", raw_data[64 + acc_len:68 + acc_len])[0]
    blob.dwAlgHashLen = struct.unpack("<I", raw_data[68 + acc_len:72 + acc_len])[0]

    blob.dwHmac2KeyLen = struct.unpack("<I", raw_data[72 + acc_len:76 + acc_len])[0]
    blob.pbHmack2Key = raw_data[76 + acc_len:76 + acc_len + blob.dwHmac2KeyLen].hex()
    acc_len += blob.dwHmac2KeyLen

    blob.dwDataLen = struct.unpack("<I", raw_data[76 + acc_len:80 + acc_len])[0]
    blob.pbData = raw_data[80 + acc_len:80 + acc_len + blob.dwDataLen].hex()
    acc_len += blob.dwDataLen

    blob.dwSignLen = struct.unpack("<I", raw_data[80 + acc_len:84 + acc_len])[0]
    blob.pbSign = raw_data[84 + acc_len:84 + acc_len + blob.dwSignLen].hex()
    acc_len += blob.dwSignLen

    assert len(raw_data) == acc_len + 84, "bad blob data!"

    return blob


def HandleCredentialFile(file_path):
    assert os.path.exists(file_path), "credential file not exist!"
    raw_credential = utils.readFile(file_path)
    if len(raw_credential) < 84:
        print("not a valid credential file")
        return None

    enc_cred = DPAPI_ENCRYPTED_CRED()
    enc_cred.version = struct.unpack("<I", raw_credential[0:4])[0]

    enc_cred.blockSize = struct.unpack("<I", raw_credential[4:8])[0]
    enc_cred.blob = HandleBlob(enc_cred.blob, raw_credential[12:])

    return enc_cred


def HandleGMTTime(time_obj: FILE_TIME, raw_data: bytes):
    assert len(raw_data) == 8, 'wrong GMT Format!'
    time_obj.dwLowDateTime = struct.unpack("I", raw_data[0:4])[0]
    time_obj.dwHighDateTime = struct.unpack("I", raw_data[4:8])[0]
    try:
        date = dt.datetime(1601, 1, 1, 0, 0, 0)
        tmp = time_obj.dwHighDateTime
        tmp <<= 32
        tmp |= time_obj.dwLowDateTime
        date = date + dt.timedelta(microseconds=tmp / 10)
        time_obj._file_time = str(date)
    except OverflowError:
        print('date convert overflow!')
        return None
    return time_obj


def DecodeCharSet(raw_data: bytes):
    if not len(raw_data):
        return '(null)'
    try:
        data = str(raw_data.decode('utf-16').replace('\0', '')).encode('gb2312')
        data = str(data, encoding='utf-8')
    except UnicodeError:
        try:
            data = str(raw_data, encoding='utf-8')
            if not data.isprintable():
                Warning("charset is not printable")
        except UnicodeDecodeError:
            return '(error)'
    return data


def HandleCRED_BLOB(raw_data: bytes):
    if len(raw_data) < 72:
        print('cred blob is not valid!')
        return None
    cred_blob = CRED_BLOB()
    cred_blob.credFlags = struct.unpack("<I", raw_data[0:4])[0]
    cred_blob.credSize = struct.unpack("<I", raw_data[4:8])[0]
    cred_blob.credUnk0 = struct.unpack("<I", raw_data[8:12])[0]
    cred_blob.Type = struct.unpack("<I", raw_data[12:16])[0]
    cred_blob.Flags = struct.unpack("<I", raw_data[16:20])[0]
    cred_blob.LastWritten = HandleGMTTime(cred_blob.LastWritten, raw_data[20:28])
    cred_blob.unkFlagsOrSize = struct.unpack("<I", raw_data[28:32])[0]
    cred_blob.Persist = struct.unpack("<I", raw_data[32:36])[0]
    cred_blob.AttributeCount = struct.unpack("<I", raw_data[36:40])[0]

    cred_blob.unk0 = struct.unpack("<I", raw_data[40:44])[0]
    cred_blob.unk1 = struct.unpack("<I", raw_data[44:48])[0]

    cred_blob.dwTargetName = struct.unpack("<I", raw_data[48:52])[0]
    acc_len = cred_blob.dwTargetName

    assert acc_len < len(raw_data), "Decrypt Error"

    cred_blob.TargetName = DecodeCharSet(raw_data[52:52 + cred_blob.dwTargetName])

    cred_blob.dwTargetAlias = struct.unpack("<I", raw_data[52 + acc_len:56 + acc_len])[0]
    cred_blob.TargetAlias = DecodeCharSet(raw_data[56 + acc_len:56 + acc_len + cred_blob.dwTargetAlias])
    acc_len += cred_blob.dwTargetAlias
    assert acc_len < len(raw_data), "Decrypt Error"

    cred_blob.dwComment = struct.unpack("<I", raw_data[56 + acc_len:60 + acc_len])[0]
    cred_blob.Comment = DecodeCharSet(raw_data[60 + acc_len:60 + acc_len + cred_blob.dwComment])
    acc_len += cred_blob.dwComment

    assert acc_len < len(raw_data), "Decrypt Error"

    cred_blob.dwUnkData = struct.unpack("<I", raw_data[60 + acc_len:64 + acc_len])[0]
    cred_blob.UnkData = DecodeCharSet(raw_data[64 + acc_len:64 + acc_len + cred_blob.dwUnkData])
    acc_len += cred_blob.dwUnkData

    cred_blob.dwUserName = struct.unpack("<I", raw_data[64 + acc_len:68 + acc_len])[0]
    cred_blob.UserName = DecodeCharSet(raw_data[68 + acc_len:68 + acc_len + cred_blob.dwUserName])
    acc_len += cred_blob.dwUserName

    assert acc_len < len(raw_data), "Decrypt Error"

    cred_blob.CredentialBlobSize = struct.unpack("<I", raw_data[68 + acc_len:72 + acc_len])[0]
    cred_blob.CredentialBlob = DecodeCharSet(raw_data[72 + acc_len:72 + acc_len + cred_blob.CredentialBlobSize])
    acc_len += cred_blob.CredentialBlobSize

    return cred_blob


def DecryptCrenFile(blob: DPAPI_BLOB, masterKey: str):
    SHA1_Key = cutils.SHA1(bytes.fromhex(masterKey))
    salt = blob.pbSalt
    out_key = bytes.fromhex(cutils.HMAC_SHA512(bytes.fromhex(SHA1_Key), bytes.fromhex(salt)))
    key_len = blob.dwAlgCryptLen // 8
    assert key_len <= len(out_key), "Key is too long!"
    out_key = out_key[:key_len]
    IV = '00000000000000000000000000000000'
    output = cutils.DecryptAES_CBC(out_key, bytes.fromhex(blob.pbData), bytes.fromhex(IV))

    return output
