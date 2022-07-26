import base64
import binascii
import getpass
import hashlib
import os
import shutil
from ctypes import c_uint32
from Cryptodome.Util.Padding import pad
from Cryptodome.Cipher import AES
import winreg
import wmi

BYTE = 0xFF
DWORD = 0xFFFFFFFF
QWORD = 0xFFFFFFFFFFFFFFFF
tmp_dir = './360se_cache/'


def _ZIMU(d1: int, d2: int):
    return (d1 * d2) & DWORD


def _ZOO3(d1: int, d2: int):
    return _ZIMU(d2, d1 >> 16) & DWORD


def _ZOO1(d1: int, d2: int, d3: int):
    return (_ZIMU(d2, d1) - _ZOO3(d1, d3)) & DWORD


def _ZOO2(d1: int, d2: int, d3: int):
    return (_ZIMU(d2, d1) + _ZOO3(d1, d3)) & DWORD


def CS64_WordSwap(Src: bytes, iChNum, iMd5: list) -> (bool, bytes):
    assert len(iMd5) == 2, 'error parameter'
    if iChNum < 2 or iChNum & 1:
        return False, 0, 0
    dwMD50 = ((iMd5[0] | 1) + 0x69FB0000) & DWORD
    dwMD51 = ((iMd5[1] | 1) + 0x13DB0000) & DWORD

    dwRet0 = 0
    dwRet1 = 0
    i = 0
    while i < iChNum:
        dwTemp00 = dwRet0
        if i < iChNum:
            dwTemp00 += int.from_bytes(Src[i * 4:(i + 1) * 4], byteorder='little')
            dwTemp00 &= DWORD
        dwTemp01 = _ZOO1(dwTemp00, dwMD50, 0x10FA9605)
        dwTemp02 = _ZOO2(dwTemp01, 0x79F8A395, 0x689B6B9F)
        dwTemp03 = _ZOO1(dwTemp02, 0xEA970001, 0x3C101569)
        i += 1
        ##################################################
        dwTemp04 = dwTemp03

        if i < iChNum:
            dwTemp04 += int.from_bytes(Src[i * 4:(i + 1) * 4], byteorder='little')
            dwTemp04 &= DWORD
        dwTemp05 = _ZOO1(dwTemp04, dwMD51, 0x3CE8EC25)
        dwTemp06 = _ZOO1(dwTemp05, 0x59C3AF2D, 0x2232E0F1)
        dwTemp07 = _ZOO2(dwTemp06, 0x1EC90001, 0x35BD1EC9)
        i += 1
        #################################################
        dwRet0 = dwTemp07
        dwRet1 = (dwTemp03 + dwRet0 + dwRet1) & DWORD

    return True, dwRet0.to_bytes(4, byteorder='little', signed=False) + \
           dwRet1.to_bytes(4, byteorder='little', signed=False)


def CS64_Reversible(Src: bytes, iChNum, Md5: list) -> (bool, bytes):
    assert len(Md5) == 2, 'error parameter'
    if iChNum < 2 or iChNum & 1:
        return False
    dwMD50 = Md5[0] | 1
    dwMD51 = Md5[1] | 1

    dwRet0 = 0
    dwRet1 = 0
    i = 0
    while i < iChNum:
        dwTemp00 = dwRet0
        if i < iChNum:
            dwTemp00 += int.from_bytes(Src[i * 4:(i + 1) * 4], byteorder='little')
        dwTemp01 = (dwMD50 * dwTemp00) & DWORD
        dwTemp02 = _ZOO1(dwTemp01, 0xB1110000, 0x30674EEF)
        dwTemp03 = _ZOO1(dwTemp02, 0x5B9F0000, 0x78F7A461)
        dwTemp04 = _ZOO2(dwTemp03, 0xB96D0000, 0x12CEB96D)
        dwTemp05 = _ZOO2(dwTemp04, 0x1D830000, 0x257E1D83)
        i += 1
        ##################################################
        dwTemp06 = dwTemp05
        if i < iChNum:
            dwTemp06 += int.from_bytes(Src[i * 4:(i + 1) * 4], byteorder='little')
            dwTemp06 &= DWORD
        dwTemp07 = (dwMD51 * dwTemp06) & DWORD
        dwTemp08 = _ZOO1(dwTemp07, 0x16F50000, 0x5D8BE90B)
        dwTemp09 = _ZOO1(dwTemp08, 0x96FF0000, 0x2C7C6901)
        dwTemp10 = _ZOO2(dwTemp09, 0x2B890000, 0x7C932B89)
        dwTemp11 = _ZOO1(dwTemp10, 0x9F690000, 0x405B6097)
        i += 1
        ##################################################
        dwRet0 = dwTemp11
        dwRet1 = (dwTemp05 + dwRet0 + dwRet1) & DWORD

    return True, dwRet0.to_bytes(4, byteorder='little', signed=False) + \
           dwRet1.to_bytes(4, byteorder='little', signed=False)


def _360Hash(Src: bytes, dwWsLen: int, iMd5: list) -> (bool, int):
    dwCount = dwWsLen // 4
    if dwCount & 1:
        dwCount -= 1
    flag1, r1 = CS64_WordSwap(Src, dwCount, iMd5)
    flag2, r2 = CS64_Reversible(Src, dwCount, iMd5)
    if not flag1 or not flag2:
        return False, 0
    res = b''
    for i in range(8):
        res += (r1[i] ^ r2[i]).to_bytes(1, 'little')
    return True, res


def EncodeWCHAR(data: str):
    new_data = ''
    for i in data:
        new_data += i + '\0'
    return new_data


def Urlenc(data: bytes):
    reserved = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-.:/'
    ret = b''
    for char in data:
        if chr(char) in reserved:
            ret += char.to_bytes(1, 'little')
        elif char == 32:
            ret += b'+'
        else:
            ret += b'%%%02x' % char
    return ret


def Rand(seed: int):
    r = (0x343fd * seed + 0x269ec3) & DWORD
    return r


def RandEnc(data: bytes, mseed: int = 0x8000402b):
    # 0x8000402b
    tmp10 = mseed.to_bytes(4, byteorder='little')
    size = len(data)
    tmp00 = size
    size = size >> 2
    count = 0
    seed = mseed
    while size > 0:
        seed = Rand(seed)
        seed1 = seed.to_bytes(4, byteorder='little')
        for i in range(4):
            tmp10 += (data[count + i] ^ seed1[i]).to_bytes(1, byteorder='little')
        count += 4
        size -= 1
    seed1 = Rand(seed)
    seed1 = seed1.to_bytes(4, byteorder='little')

    for i in range(tmp00 & 3):
        tmp10 += (data[count + i] ^ seed1[i]).to_bytes(1, byteorder='little')

    return tmp10


def TeaEncrypt(iv: bytes, key: bytes):
    seed = 0x9e3779b9
    v4 = c_uint32(int.from_bytes(iv[0:4], 'little'))
    v5 = c_uint32(int.from_bytes(iv[4:8], 'little'))

    key0 = int.from_bytes(key[0:4], 'little')
    key1 = int.from_bytes(key[4:8], 'little')
    key2 = int.from_bytes(key[8:12], 'little')
    key3 = int.from_bytes(key[12:16], 'little')

    for i in range(8):
        v4.value += ((key0 + 0x10 * v5.value) ^ (v5.value + seed) ^ (key1 + (v5.value >> 5)))
        v5.value += ((key2 + 0x10 * v4.value) ^ (v4.value + seed) ^ (key3 + (v4.value >> 5)))
        seed -= 0x61c88647
        seed &= DWORD

    return v4.value, v5.value


def Tea360(pbData: bytes, size=0x80):
    datasz = len(pbData)
    if size > datasz:
        pbData += b'\x00' * (size - datasz)
        datasz = size

    keys = b''
    datas = b''
    for i in range(0, datasz, 4):
        num = int.from_bytes(pbData[i:i + 4], 'little')
        if i < 16:
            keys += num.to_bytes(4, 'little')
        datas += num.to_bytes(4, 'little')

    bs = b''
    for j in range(0, len(datas), 8):
        x, y = TeaEncrypt(datas[j:j + 8], keys)
        bs += x.to_bytes(4, 'little')
        bs += y.to_bytes(4, 'little')
    return bs


def GetMachineGuid():
    MachineGuidKey = winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE,
        'SOFTWARE\\Microsoft\\Cryptography',
        0,
        winreg.KEY_READ | winreg.KEY_WOW64_64KEY
    )
    MachineGuid = winreg.QueryValueEx(MachineGuidKey, 'MachineGuid')[0]
    return MachineGuid


def GetSID():
    whoami = wmi.WMI()
    users = whoami.Win32_UserAccount()
    for u in users:
        if u.Name == os.getlogin():
            return u.SID
    return None


def GetBookMark():
    username = getpass.getuser()
    install_path = f'C:/Users/{username}/AppData/Roaming/360se6/'
    if not os.path.exists(install_path):
        print('360 safe browser maybe not installed!')
        return None
    bookmark_path = os.path.join(install_path, 'User Data/Default/360Bookmarks')
    if not os.path.exists(bookmark_path):
        print('no bookmark found!')
        return None
    else:
        if not os.path.exists(tmp_dir):
            os.mkdir(tmp_dir)
        file_name = bookmark_path.split('/')[-1].split('\\')[-1]
        file_path = os.path.join(tmp_dir, file_name)
        if not os.path.exists(file_path):
            shutil.copy(bookmark_path, file_path)
        assert os.path.exists(file_path), "database file copy failed!"

        with open(bookmark_path, 'rb') as f:
            content = f.read()
        f.close()
        return content


def DecryptLocal360Chrome():
    stub = [0x1f, 0x7d, 0x14, 0x89, 0x4d, 0xb8, 0x8b, 0x4d, 0x18, 0x89, 0x45, 0xbc, 0x89, 0x7d, 0xb0, 0x89,
            0x4d, 0xac, 0x89, 0x5d, 0xd0, 0x89, 0x5d, 0xc8, 0x88, 0x5d, 0xd7, 0x88, 0x5d, 0xc0, 0x3b, 0xfb,
            0x0f, 0x84, 0x77, 0x93, 0x03, 0x00, 0x89, 0x90, 0x8b, 0x4e, 0x10, 0xf7, 0x41, 0x08, 0x00, 0x40,
            0x00, 0x00, 0x0f, 0x84, 0x6f, 0x93, 0x03, 0x00, 0xf7, 0x46, 0x68, 0x00, 0x01, 0x00, 0x00, 0x0f,
            0x85, 0x58, 0xcc, 0x03, 0x00, 0xf6, 0x05, 0xa0, 0x03, 0xfe, 0x7f, 0x01, 0xbf, 0x00, 0x01, 0x00,
            0x02, 0x0f, 0x85, 0x4f, 0x96, 0x03, 0x00, 0x89, 0x5d, 0xd8, 0x85, 0x7e, 0x68, 0x0f, 0x85, 0x8b,
            0x96, 0x03, 0x00, 0x38, 0x5e, 0x02, 0x0f, 0x85, 0xea, 0x96, 0xcc, 0x00, 0xeb, 0x1d, 0x39, 0x5d,
            0xc8, 0x0f, 0x85, 0x3b, 0x97, 0x03, 0x00, 0x8b, 0x45, 0xd8, 0x8b, 0x4d, 0xfc, 0x5f, 0x5e, 0x33,
            0x10, 0x00, 0x00, 0x00, 0x57, 0x00, 0x44, 0x00, 0x4c, 0x00, 0x32, 0x00, 0x30, 0x00, 0x31, 0x00,
            0x36, 0x00, 0x00, 0x00]
    stub = bytes(stub)
    # step 1
    payload_one = b''
    payload_one += stub

    sid = GetSID()
    payload_one += EncodeWCHAR(sid).encode()
    payload_one += EncodeWCHAR('/?').encode()
    machine_guid = GetMachineGuid()
    payload_one += EncodeWCHAR(machine_guid).encode()

    # step 2
    md5_payload_one = hashlib.md5(payload_one).digest()

    a = int.from_bytes(md5_payload_one[0:4], 'little')
    b = int.from_bytes(md5_payload_one[4:8], 'little')

    flag, mhashbs = _360Hash(payload_one, len(payload_one), [a, b])
    assert flag, '360 hash err!'
    mhash_encbs = Urlenc(base64.b64encode(mhashbs))

    # step 3
    payload_two = b''
    payload_two += int.to_bytes(1, 4, 'little')
    payload_two += int.to_bytes(len(stub), 4, 'little')
    payload_two += stub
    payload_two += int.to_bytes(2, 4, 'little')
    payload_two += int.to_bytes(len(mhash_encbs), 4, 'little')
    payload_two += mhash_encbs

    # step 4
    randenc_bs = RandEnc(payload_two, 0x8000402b)
    tmp_bs = hashlib.md5(randenc_bs).digest()

    # step 5
    tmp_bs = Tea360(binascii.b2a_hex(tmp_bs))
    tmp_bs = pad(tmp_bs, 0xc0 + 1, 'x923')[:-1]
    key_bs = hashlib.md5(tmp_bs).digest()

    # step 6
    bookmark = GetBookMark()
    if bookmark:
        iv = b'33mhsq0uwgzblwdo'
        aes = AES.new(key=binascii.b2a_hex(key_bs), iv=iv, mode=AES.MODE_CBC)
        bs = base64.b64decode(bookmark)[4:]
        bs = aes.decrypt(bs)
        return bs.decode()
    else:
        return ''


def ClearCache():
    if os.path.exists(tmp_dir):
        shutil.rmtree(tmp_dir)
    if not os.path.exists(tmp_dir):
        os.mkdir(tmp_dir)


def GetBookMarksBy360SafeAuto():
    print('360 Safe Browser')
    ClearCache()
    print(DecryptLocal360Chrome())

