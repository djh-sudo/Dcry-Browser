import binascii
import os
import re
import json
import getpass
import sqlite3
import shutil
import cutils
from hashlib import pbkdf2_hmac
from pyasn1.codec.der import decoder
import base64


tmp_dir = 'firefox_cache/'
CKA_ID = b'\xf8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'


def TryToGetDataBase():
    full_path = []
    username = getpass.getuser()
    file_path = f'C:/Users/{username}/AppData/Roaming/Mozilla/Firefox/Profiles/'
    if os.path.exists(file_path):
        for path, dirs, file_name in os.walk(file_path):
            for dir_name in dirs:
                if '.default' in dir_name:
                    full_path.append(os.path.join(path, dir_name))
                else:
                    continue
        if full_path:
            return full_path
        else:
            print('No user password file!')
            return None
    else:
        print('Firefox may not be installed!')
        return None


def TryToGetDBAndKey(base_path: str):
    key_path = ''
    db_path = ''

    pattern = r'key[3-4]{1}\.db'
    for file_name in os.listdir(base_path):
        if re.match(pattern, file_name):
            key_path = os.path.join(base_path, file_name)
        if file_name == 'logins.json':
            db_path = os.path.join(base_path, file_name)

    if not db_path or not key_path:
        print(f'lack key or db file, pls check {base_path}')

    return key_path, db_path


def GetKeyFromDB(db_file_path: str):
    if not os.path.exists(tmp_dir):
        os.mkdir(tmp_dir)
    file_name = db_file_path.split('/')[-1].split('\\')[-1]
    file_db = tmp_dir + file_name
    if not os.path.exists(file_db):
        shutil.copy(db_file_path, file_db)
    assert os.path.exists(file_db), 'key database copy failed!'

    try:
        db = sqlite3.connect(file_db)
        cursor = db.cursor()
        cursor.execute("SELECT item1,item2 FROM metadata WHERE id = 'password'")
        row = cursor.fetchone()
        global_salt = row[0]
        password_check = row[1]
        decoded = decoder.decode(password_check)
        check, info = DecryptKey(decoded, global_salt)
        if binascii.a2b_hex(check) == b'password-check\x02\x02':
            cursor.execute('SELECT a11,a102 FROM nssPrivate')
            row = cursor.fetchone()
            a11 = row[0]
            a102 = row[1]
            if a11 and a102 == CKA_ID:
                decoded = decoder.decode(a11)
                master_key, algorithm = DecryptKey(decoded, global_salt)
                master_key = bytes.fromhex(master_key)
                assert len(master_key) >= 24, 'master key length error'
                return master_key[:24], algorithm
            else:
                print('No saved master key!')
        else:
            print('password check failed!')
            return None
    except Exception as ex:
        print(ex)


def DecryptKey(payload, global_salt: bytes, master_key=b''):
    """
"2A864886F70D010C050103","1.2.840.113549.1.12.5.1.3 pbeWithSha1AndTripleDES-CBC"
"2A864886F70D0307","1.2.840.113549.3.7 des-ede3-cbc"
"2A864886F70D010101","1.2.840.113549.1.1.1 pkcs-1"
"2A864886F70D01050D","1.2.840.113549.1.5.13 pkcs5 pbes2"
"2A864886F70D01050C","1.2.840.113549.1.5.12 pkcs5 PBKDF2"
"2A864886F70D0209","1.2.840.113549.2.9 hmacWithSHA256"
"60864801650304012A","2.16.840.1.101.3.4.1.42 aes256-CBC"
    """

    algorithm = str(payload[0][0][0])
    if algorithm == '1.2.840.113549.1.5.13':
        assert str(payload[0][0][1][0][0]) == '1.2.840.113549.1.5.12', 'error encode[pkcs5 PBKDF2]'
        assert str(payload[0][0][1][0][1][3][0]) == '1.2.840.113549.2.9', 'error encode[hmacWithSHA256]'
        assert str(payload[0][0][1][1][0]) == '2.16.840.1.101.3.4.1.42', 'error encode[aes256-CBC]'

        entry_salt = payload[0][0][1][0][1][0].asOctets()
        rounds = int(payload[0][0][1][0][1][1])
        key_len = int(payload[0][0][1][0][1][2])

        assert key_len == 32, 'key len error'

        hashed_password = cutils.SHA1(global_salt + master_key)
        key = pbkdf2_hmac('sha256', bytes.fromhex(hashed_password), entry_salt, rounds, key_len)

        IV = b'\x04\x0e' + payload[0][0][1][1][1].asOctets()

        cipherT = payload[0][1].asOctets()

        plain_text = cutils.DecryptAES_CBC(key, cipherT, IV)
        return plain_text, algorithm
    else:
        print('Version not support!')
        return None


def GetLoginData(base_path: str):
    json_file = os.path.join(base_path, 'logins.json')
    db_file = os.path.join(base_path, 'signons.sqlite')
    if os.path.exists(json_file):
        file = open(json_file, 'r', encoding='utf-8').read()
        logins = json.loads(file)
        if 'logins' not in logins:
            print('not a valid login file')
            return
        else:
            res_file = []
            for row in logins['logins']:
                enc_username = row['encryptedUsername']
                enc_password = row['encryptedPassword']
                url = row['hostname']
                res_file.append((url, DecodeLoginData(enc_username), DecodeLoginData(enc_password)))
            return res_file
    elif os.path.exists(db_file):
        print('Version not support!')
    else:
        print('not login file!')


def DecodeLoginData(raw_data: str):
    ans1_data = decoder.decode(base64.b64decode(raw_data))
    key_id = ans1_data[0][0].asOctets()
    iv = ans1_data[0][1][1].asOctets()
    cipher = ans1_data[0][2].asOctets()
    return key_id, iv, cipher


def DecryptLoginData(key: bytes, cipher: bytes, iv: bytes):
    data = cutils.Decrypt_3DES_CBC(key, cipher, iv)
    padding = data[-1]
    if data.count(padding.to_bytes(1, byteorder='little')) == padding:
        data = data[:-int(padding)]
        return data
    else:
        return ''


def GetPasswordByFireFoxAuto():
    print('Firefox Browser')
    ClearCache()
    full_path = TryToGetDataBase()
    for base_path in full_path:
        key_path, db_path = TryToGetDBAndKey(base_path)
        if os.path.exists(key_path):
            key, alg = GetKeyFromDB(key_path)
            logins = GetLoginData(base_path)
            for item in logins:
                assert item[1][0] == CKA_ID, 'invalid username'
                assert item[2][0] == CKA_ID, 'invalid password'
                iv = item[1][1]
                cipher = item[1][2]
                user = DecryptLoginData(key, cipher, iv)
                iv = item[2][1]
                cipher = item[2][2]
                password = DecryptLoginData(key, cipher, iv)
                print(user, password, item[0])
        else:
            continue


def ClearCache():
    if os.path.exists(tmp_dir):
        shutil.rmtree(tmp_dir)
    if not os.path.exists(tmp_dir):
        os.mkdir(tmp_dir)