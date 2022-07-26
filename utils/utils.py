import os
import re
import getpass
from FileFormat import *
from argparse import ArgumentParser


def readFile(file_path: str):
    h_file = open(file_path, 'rb')
    file_content = h_file.read()
    return file_content


def EncodeWCHAE(data):
    assert data
    new_data = ''
    for i in data:
        new_data += i + '\0'
    return new_data


def HandleGUID(guid: GUID, raw_data: bytes):
    assert len(raw_data) == 16, "guid is not valid!"
    guid.Data1 = raw_data[0:4][::-1].hex()
    guid.Data2 = raw_data[4:6][::-1].hex()
    guid.Data3 = raw_data[6:8][::-1].hex()
    guid.Data4 = raw_data[8:16].hex()
    res = guid.Data1 + '-' + guid.Data2 + '-' + guid.Data3 + '-' + guid.Data4[:4] + '-' + guid.Data4[4:]
    return guid, res


def TryGetUserCredentials():
    # Windows Credentials Folders
    sc_path = []
    user = getpass.getuser()
    user_names = {'Administrator', user}
    dir_names = {'Local', 'Roaming'}
    for dirname in dir_names:
        for username in user_names:
            user_path = f'C:/Users/{username}/AppData/{dirname}/Microsoft/Credentials'
            if os.path.exists(user_path) and user_path not in sc_path:
                sc_path.append(user_path)

    # find credential file
    cred_file_list = []
    for dir_path in sc_path:
        for file_name in os.listdir(dir_path):
            if len(file_name) == 32 and file_name.isalnum():
                full_path = dir_path + '/' + file_name
                cred_file_list.append(full_path)
    if len(cred_file_list) == 0:
        print('Get Credentials file failed!')
    return cred_file_list


def TryGetMasterKeyFile():
    # Windows Protected File
    sc_path = ['C:/Windows/System32/Microsoft/Protect']
    user = getpass.getuser()
    user_names = {'Administrator', user}
    dir_names = {'Local', 'Roaming'}
    for dirname in dir_names:
        for username in user_names:
            user_path = f'C:/Users/{username}/AppData/{dirname}/Microsoft/Protect'
            if os.path.exists(user_path):
                sc_path.append(user_path)
    sid_file = {}
    # master key file
    pattern = r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    for dir_path in sc_path:
        for file_name in os.listdir(dir_path):
            full_path = dir_path + '/' + file_name
            if file_name.startswith('S-1-') and os.path.isdir(full_path):
                sid_file[file_name] = []
                for sub_file in os.listdir(full_path):
                    if len(sub_file) == 36 and re.match(pattern, sub_file):
                        tmp_path = full_path + '/' + sub_file
                        sid_file[file_name].append(tmp_path)

    if len(sid_file) == 0:
        print('Get master key file failed!')
    return sid_file


def exec(parser: ArgumentParser):
    args = parser.parse_args()
    search_key = args.searchKey
    search_cred = args.searchCred
    if search_key:
        print('** Master Key File **')
        sid_file = TryGetMasterKeyFile()
        for sid in sid_file:
            print('**{', sid, '**}')
            for full_path in sid_file[sid]:
                print(full_path)
    if search_cred:
        print('** Credentials Files **')
        credentials = TryGetUserCredentials()
        for full_path in credentials:
            print(full_path)


