class GUID:
    def __init__(self):
        self.Data1 = b''            # 4 bytes
        self.Data2 = b''            # 2 bytes
        self.Data3 = b''            # 2 bytes
        self.Data4 = b''            # 8 bytes


class DPAPI_MASTERKEY:
    def __init__(self):
        self.dwVersion = b''        # 4 bytes
        self.salt = b''             # 16 bytes
        self.rounds = b''           # 4 bytes
        self.algHash = b''          # 4 bytes
        self.algCrypt = b''         # 4 bytes
        self.pbKey = b''            # not fixed
        self._dwKeyLen = b''        # not exist
        self._masterkey = b''       # not exist

    def info(self):
        print('** Master Key')
        print('dwVersion:', self.dwVersion)
        print('salt:', self.salt)
        print('rounds:', self.rounds)
        print('algHash:', self.algHash)
        print('algCrypt:', self.algCrypt)
        print('pbKey:', self.pbKey)


class DPAPI_MASTERKEY_DOMAINKEY:
    def __init__(self):
        self.dwVersion = b''        # 4 bytes
        self.dwSecrete = b''        # 4 bytes
        self.dwAccesscheckLen = b'' # 4 bytes
        self.guidMasterKey = b''    # 16 bytes
        self.pbSecrete = b''        # not fixed
        self.pbAccesscheck = b''    # not fixed

    def info(self):
        # TODO
        pass


class DPAPI_MASTERKEY_CREDHIST:
    def __init__(self):
        self.dwVersion = b''        # 4 bytes
        self.guid = GUID()          # 16 bytes
        self._guid = b''           # not exist

    def info(self):
        print('** Credentials Info:')
        print('dwVersion:', self.dwVersion)
        print('guid:', self._guid)


class DPAPI_MASTERKEYS:
    def __init__(self):
        self.valid = False          # not exist

        self.dwVersion = b''        # 4 bytes
        
        self.unk0 = b''             # 4 bytes
        self.unk1 = b''             # 4 bytes
        
        self.szGuid = b''           # 36 * 2 bytes
        
        self.unk2 = b''             # 4 bytes
        self.unk3 = b''             # 4 byte
        
        self.dwFlags = b''          # 4 bytes
        
        self.dwMasterKeyLen = b''   # 8 bytes
        self.dwBackupKeyLen = b''   # 8 bytes
        self.dwCreHistLen = b''     # 8 bytes
        self.dwDomainKeyLen = b''   # 8 bytes
        
        self.MasterKey = DPAPI_MASTERKEY()
        self.BackKey = DPAPI_MASTERKEY()
        self.CredHist = DPAPI_MASTERKEY_CREDHIST()
        self.DomainKey = DPAPI_MASTERKEY_DOMAINKEY()

    def info(self):
        print('** Master Keys **')
        print('dwVersion:', self.dwVersion)
        print('szGuid:', self.szGuid)
        print('dwFlags:', self.dwFlags)
        print('dwMasterKeyLen:', self.dwMasterKeyLen)
        print('dwBackupKeyLen:', self.dwBackupKeyLen)
        print('dwCreHistLen:', self.dwCreHistLen)
        print('dwDomainKeyLen', self.dwDomainKeyLen)
        self.MasterKey.info()
        self.BackKey.info()
        self.CredHist.info()


class DPAPI_ENCRYPTED_CRED:
    def __init__(self):
        self.version = b''          # 4 bytes
        self.blockSize = b''        # 4 bytes
        self.unk = b''              # 4 bytes
        self.blob = DPAPI_BLOB()    # not fixed


class DPAPI_BLOB:
    def __init__(self):
        self.dwVersion = b''            # 4 bytes
        self.guidProvider = GUID()      # 16 bytes
        self._guidProvider = b''        # not exist
        self.dwMasterKeyVersion = b''   # 4 bytes
        self.guidMasterKey = GUID()     # 16 bytes
        self._guidMasterKey = b''       # not exist
        self.dwFlags = b''              # 4 bytes

        self.dwDescriptionLen = b''     # 4 bytes
        self.szDescription = b''        # not fixed

        self.algCrypt = b''             # 4 byte
        self.dwAlgCryptLen = b''        # 4 bytes

        self.dwSaltLen = b''            # 4 bytes
        self.pbSalt = b''               # not fixed

        self.dwHmacKeyLen = b''         # 4 bytes
        self.pbHmackKey = b''           # not fixed

        self.algHash = b''              # 4 byte
        self.dwAlgHashLen = b''         # 4 bytes

        self.dwHmac2KeyLen = b''        # 4 bytes
        self.pbHmack2Key = b''          # not fixed

        self.dwDataLen = b''            # 4 byte
        self.pbData = b''               # not fixed

        self.dwSignLen = b''            # 4 bytes
        self.pbSign = b''               # not fixed

    def info(self):
        print('** BLOB **')
        print('dwVersion:', self.dwVersion)
        print('guidProvider:', self._guidProvider)
        print('dwMasterKeyVersion:', self.dwMasterKeyVersion)
        print('guidMasterKey:', self._guidMasterKey)
        print('dwFlags:', self.dwFlags)
        print('dwDescriptionLen', self.dwDescriptionLen)
        print('szDescription:', self.szDescription)
        print('algCrypt', self.algCrypt)
        print('dwAlgCryptLen:', self.dwAlgCryptLen)
        print('dwSaltLen:', self.dwSaltLen)
        print('pbSalt:', self.pbSalt)
        print('dwHmacKeyLen:', self.dwHmacKeyLen)
        print('pbHmackKey:', self.pbHmackKey)
        print('algHash:', self.algHash)
        print('dwAlgHashLen:', self.dwAlgHashLen)
        print('dwHmac2KeyLen:', self.dwHmac2KeyLen)
        print('pbHmack2Key:', self.pbHmack2Key)
        print('dwDataLen:', self.dwDataLen)
        print('pbData:', self.pbData)
        print('dwSignLen:', self.dwSignLen)
        print('pbSign', self.pbSign)


class FILE_TIME:
    def __init__(self):
        self.dwLowDateTime = b''        # 4 bytes
        self.dwHighDateTime = b''       # 4 bytes
        self._file_time = b''           # not exist


class CRED_BLOB:
    def __init__(self):
        self.credFlags = b''            # 4 bytes
        self.credSize = b''             # 4 bytes
        self.credUnk0 = b''             # 4 bytes

        self.Type = b''                 # 4 bytes
        self.Flags = b''                # 4 bytes
        self.LastWritten = FILE_TIME()  # 8 bytes
        self.unkFlagsOrSize = b''       # 4 bytes
        self.Persist = b''              # 4 bytes
        self.AttributeCount = b''       # 4 bytes
        self.unk0 = b''                 # 4 bytes
        self.unk1 = b''                 # 4 bytes

        self.dwTargetName = b''         # 4 bytes
        self.TargetName = b''           # not fixed
        self.dwTargetAlias = b''        # 4 bytes
        self.TargetAlias = b''          # not fixed

        self.dwComment = b''            # 4 bytes
        self.Comment = b''              # not fixed

        self.dwUnkData = b''            # 4 bytes
        self.UnkData = b''              # not fixed

        self.dwUserName = b''           # 4 bytes
        self.UserName = b''             # not fixed

        self.CredentialBlobSize = b''   # 4 bytes
        self.CredentialBlob = b''       # not fixed

        self.Attributes = b''           # not fixed[ignore]

    def info(self):
        print('** Credentials **')
        print('credFlags:', self.credFlags)
        print('credSize:', self.credSize)
        print('credUnk0:', self.credUnk0)
        print('Type:', self.Type)
        print('Flags:', self.Flags)
        print('LastWritten:', self.LastWritten._file_time)
        print('unkFlagsOrSize:', self.unkFlagsOrSize)
        print('Persist:', self.Persist)
        print('AttributeCount:', self.AttributeCount)
        print('unk0:', self.unk0)
        print('unk1:', self.unk1)
        print('TargetName:', self.TargetName)
        print('TargetAlias:', self.TargetAlias)
        print('Comment:', self.Comment)
        print('UnkData:', self.UnkData)
        print('UserName:', self.UserName)
        print('CredentialBlob:', self.CredentialBlob)
