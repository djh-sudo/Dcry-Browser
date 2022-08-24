#pragma once
#include <string>
#include <vector>
#include <Windows.h>
#include "CipherHelper.h"


/*
* credential file is store at
* C:/Users/%username%/AppData/Roaming/Microsoft/Credentials
* maybe also exists at local directory ?
* This header file is about DPAPI BLOB
* Keywords: CREDENTIALS
* Also See
* https://github.com/gentilkiwi/mimikatz
*/

typedef struct _DPAPI_ENCRYPTED_CRED {
	DWORD version;
	DWORD blobSize;
	DWORD unk;
	BYTE blob[ANYSIZE_ARRAY];
} DPAPI_ENCRYPTED_CRED, * P_DPAPI_ENCRYPTED_CRED;


typedef struct _DPAPI_BLOB {
	/* Off[DEC]  Description */
	/* acc is unfixed length accumulated! */
	/*   00   */ DWORD dwVersion;
	/*   04   */ GUID guidProvider;
	/*   20   */ DWORD dwMasterKeyVersion;
	/*   24   */ GUID guidMasterKey;
	/*   40   */ DWORD dwFlags;
	/*   44   */ DWORD dwDescriptionLen;
	/* acc+48 */ WCHAR szDescription[ANYSIZE_ARRAY];
	/* acc+48 */ ALG_ID algCrypt;
	/* acc+52 */ DWORD dwAlgCryptLen;
	/* acc+56 */ DWORD dwSaltLen;
	/* acc+60 */ BYTE pbSalt[ANYSIZE_ARRAY];
	/* acc+60 */ DWORD dwHmacKeyLen;
	/* acc+64 */ BYTE pbHmackKey[ANYSIZE_ARRAY];
	/* acc+64 */ ALG_ID algHash;
	/* acc+68 */ DWORD dwAlgHashLen;
	/* acc+72 */ DWORD dwHmac2KeyLen;
	/* acc+76 */ BYTE pbHmack2Key[ANYSIZE_ARRAY];
	/* acc+76 */ DWORD dwDataLen;
	/* acc+80 */ BYTE pbData[ANYSIZE_ARRAY];
	/* acc+80 */ DWORD dwSignLen;
	/* acc+84 */ BYTE pbSign[ANYSIZE_ARRAY];
} DPAPI_BLOB, * P_DPAPI_BLOB;

typedef struct _CRED_ATTRIBUTE {
	/* Off[DEC] Description */
	/*  00  */   DWORD Flags;
	/*  04  */   DWORD dwKeyword;
	/*  08  */   LPWSTR Keyword;
	/*08+acc*/   DWORD ValueSize;
	/*12+acc*/   LPBYTE Value;
} CRED_ATTRIBUTE, * P_CRED_ATTRIBUTE;

#pragma pack(push, 4)
typedef struct _CRED_BLOB {
	/* Off[DEC] Description */
	/*  00  */  DWORD credFlags;
	/*  04  */  DWORD credSize;
	/*  08  */  DWORD credUnk0;
	/*  12  */  DWORD Type;
	/*  16  */  DWORD Flags;
	/*  20  */  FILETIME LastWritten;
	/*  28  */  DWORD unkFlagsOrSize;
	/*  32  */  DWORD Persist;
	/*  36  */  DWORD AttributeCount;
	/*  40  */  DWORD unk0;
	/*  44  */  DWORD unk1;
	/*  48  */  DWORD dwTargetName;
	/*  52  */  WCHAR TargetName[ANYSIZE_ARRAY];
	/*52+acc*/  DWORD dwTargetAlias;
	/*56+acc*/  WCHAR TargetAlias[ANYSIZE_ARRAY];
	/*56+acc*/  DWORD dwComment;
	/*60+acc*/  WCHAR Comment[ANYSIZE_ARRAY];
	/*60+acc*/  DWORD dwUnkData;
	/*64+acc*/  WCHAR UnkData[ANYSIZE_ARRAY];
	/*64+acc*/  DWORD dwUserName;
	/*68+acc*/  WCHAR UserName[ANYSIZE_ARRAY];
	/*68+acc*/  DWORD CredentialBlobSize;
	/*72+acc*/  WCHAR CredentialBlob[ANYSIZE_ARRAY];
	P_CRED_ATTRIBUTE* Attributes;
} CRED_BLOB, * P_CRED_BLOB;
#pragma pack(pop)


class Credentials {

public:

	bool Init(const void * memory, int dwMemory) {
		bool flag = false;
		DWORD acc = 0, dwSaltLen = 0, dwDataLen = 0, dwDescriptionLen = 0;
		do {
			if (memory == NULL || dwMemory <= sizeof(DPAPI_BLOB)) {
				break;
			}
			acc = 0;
			m_mKeyGuid = ((P_DPAPI_BLOB)((char *)memory + acc))->guidMasterKey;

			acc += ((P_DPAPI_BLOB)((char *)memory + acc))->dwDescriptionLen;
			if(acc > dwMemory){
				break;
			}
			m_dwAlgCryptLen = *(PDWORD)((char *)memory + acc + 52);
			dwSaltLen = *(PDWORD)((char *)memory + acc + 56);
			
			m_salt.resize(dwSaltLen);
			memcpy(m_salt.data(), ((char *)memory + acc + 60), dwSaltLen);
			acc += dwSaltLen;

			acc += *(PDWORD)((char *)memory + acc + 60);
			acc += *(PDWORD)((char *)memory + acc + 72);
			if (acc > dwMemory) {
				break;
			}
			dwDataLen = *(PDWORD)((char *)memory + acc + 76);
			m_encBlob.resize(dwDataLen);
			memcpy(m_encBlob.data(), ((char *)memory + acc + 80), dwDataLen);
			acc += dwDataLen;
			
			acc += *(PDWORD)((char *)memory + acc + 80);
			if (acc + 84 != dwMemory) {
				break;
			}
			flag = true;

		} while (false);

		return flag;
	}

	bool Decrypt(const void * key, int dwKey) {
		bool flag = false;
		char iv[16] = { 0 };
		do {
			std::string sha1Key = SSLHelper::sha1(key, dwKey);
			std::string outKey = SSLHelper::HMAC_SHA512(sha1Key.c_str(), SHA_DIGEST_LENGTH, m_salt.data(), m_salt.size());
			int dwOutKey = m_dwAlgCryptLen >> 3;
			if (dwOutKey > SHA512_DIGEST_LENGTH) {
				break;
			}
			outKey = outKey.substr(0, dwOutKey);
			// Decrypt
			std::string plain = SSLHelper::AesCBCDecrypt(m_encBlob.data(), m_encBlob.size(), outKey.c_str(), dwOutKey, iv);
			if (plain == "") {
				break;
			}
			if (plain.back() >= 0 && plain.back() <= 0x10) {
				int padding = plain.back(), index = plain.size();
				bool check = true;
				for (int i = 0; i < padding; ++i) {
					if (plain[index - 1 - i] != padding) {
						check = false;
						break;
					}
				}
				if (check == true) {
					plain = plain.substr(0, index - padding);
				}
			}
			m_blob.resize(plain.size());
			memcpy(m_blob.data(), plain.c_str(), plain.size());

			flag = true;

		} while (false);

		return flag;
	}

	std::string GetGUID() const {
		char guidBuffer[64] = { 0 };
		sprintf_s(guidBuffer, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x", 
			    m_mKeyGuid.Data1, m_mKeyGuid.Data2, m_mKeyGuid.Data3,
			    m_mKeyGuid.Data4[0], m_mKeyGuid.Data4[1], m_mKeyGuid.Data4[2],
			    m_mKeyGuid.Data4[3], m_mKeyGuid.Data4[4], m_mKeyGuid.Data4[5],
			    m_mKeyGuid.Data4[6], m_mKeyGuid.Data4[7]);
		return std::string(guidBuffer);
	}

	std::vector<char>& GetBlob() {
		return m_blob;
	}

	int GetBlobSize() const {
		return m_blob.size();
	}

	Credentials() {
		m_dwAlgCryptLen = 0;
		memset(&m_mKeyGuid, 0, sizeof(GUID));
	}
	
	~Credentials() = default;

private:
	
	std::vector<char>m_encBlob;
	std::vector<char>m_blob;
	
	std::vector<char>m_salt;
	GUID m_mKeyGuid;
	DWORD m_dwAlgCryptLen;
};