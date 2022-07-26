from FileFormat import *
import utils
from argparse import ArgumentParser
import MasterKey as mk
import DecryptCredentials as dc


def GetMasterKey(file_path: str, password: str, SID: str, flag=True) -> DPAPI_MASTERKEYS:
    apapi_masterkey = mk.HandleRawMasterkey(file_path)
    apapi_masterkey.MasterKey._masterkey, verify = mk.DecryptMasterKey(apapi_masterkey, password, SID)
    if flag:
        apapi_masterkey.info()
    if verify:
        apapi_masterkey.valid = True
    return apapi_masterkey


def GetCredentials(file_path: str, master_key: DPAPI_MASTERKEYS = None, flag=True):
    enc_cred = dc.HandleCredentialFile(file_path)
    if flag:
        enc_cred.blob.info()
    if master_key and master_key.valid:
        master_guid = master_key.szGuid
        guid = enc_cred.blob._guidMasterKey
        assert master_guid == guid, "masterKey and credentials not match!"

        output = dc.DecryptCrenFile(enc_cred.blob, master_key.MasterKey._masterkey)
        cred = dc.HandleCRED_BLOB(bytes.fromhex(output))
        if flag:
            cred.info()
    else:
        return enc_cred


def Search(sid_file: dict, guid: str):
    for key in sid_file:
        if guid in sid_file[key]:
            return sid_file[key].index(guid), key
    return -1, None


def HandleSIDFile(sid_file: dict):
    cache = dict()
    for key in sid_file:
        cache[key] = []
        for sid_name in sid_file[key]:
            subname = sid_name.split('/')[-1]
            cache[key].append(subname)
    return cache


def AutoGetCredentials(password: str):
    cred_files = utils.TryGetUserCredentials()
    sid_file = utils.TryGetMasterKeyFile()
    cache_sid_file = HandleSIDFile(sid_file)

    for file in cred_files:
        enc_cred = GetCredentials(file, None, False)
        guid = enc_cred.blob._guidMasterKey
        # search the master key
        index, sid = Search(cache_sid_file, guid)
        # print(sid, sid_file[sid][index])
        if sid:
            print(sid)
            master_key = GetMasterKey(sid_file[sid][index], password, sid)
            GetCredentials(file, master_key)


def exec(parser: ArgumentParser):
    args = parser.parse_args()
    auto_exec = args.auto
    decrypt_path = args.decrypt
    masterKey_path = args.masterKey
    password = args.password
    sid = args.userSid
    master_key = None

    if auto_exec and password:
        AutoGetCredentials(password)
        return
    if masterKey_path and sid and password:
        master_key = GetMasterKey(masterKey_path, password, sid)
    if decrypt_path:
        GetCredentials(decrypt_path, master_key)
