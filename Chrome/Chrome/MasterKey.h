#pragma once
#include <string>
#include <vector>
#include <Windows.h>
#include "CipherHelper.h"


/*
* master key file is store at
* C:/Users/%username%/AppData/Roaming/Microsoft/Protect/sid/
* C:/Windows/System32/appmgmt/sid/
* This header file is about MASTERKEY
* Keywords: MASTER KEY
* Also See
* https://github.com/gentilkiwi/mimikatz
*/

typedef struct _DPAPI_MASTERKEY_CREDHIST {
	/* Off[DEC] Description */
	/* 00 */    DWORD dwVersion;
	/* 04 */    GUID guid;
} DPAPI_MASTERKEY_CREDHIST, * P_DPAPI_MASTERKEY_CREDHIST;

typedef struct _DPAPI_MASTERKEY_DOMAINKEY {
	/* Off[DEC] Description */
	/* 00 */    DWORD dwVersion;
	/* 04 */    DWORD dwSecretLen;
	/* 08 */    DWORD dwAccesscheckLen;
	/* 12 */    GUID guidMasterKey;
	/* 28 */    PBYTE pbSecret;
	/* 32 */    PBYTE pbAccesscheck;
} DPAPI_MASTERKEY_DOMAINKEY, * P_DPAPI_MASTERKEY_DOMAINKEY;

typedef struct _DPAPI_MASTERKEY {
	/* Off[DEC] Description */
	/* 00 */    DWORD dwVersion;
	/* 04 */    BYTE salt[16];
	/* 20 */    DWORD rounds;
	/* 24 */    ALG_ID algHash;
	/* 28 */    ALG_ID algCrypt;
	/* 32 */    BYTE pbKey[ANYSIZE_ARRAY];
} DPAPI_MASTERKEY, * P_DPAPI_MASTERKEY;

typedef struct _DPAPI_MASTERKEYS {
	/* Off[DEC] Description */
	/* 000 */   DWORD dwVersion;
	/* 004 */   DWORD unk0;
	/* 008 */   DWORD unk1;
	/* 012 */   WCHAR szGuid[36];
	/* 048 */   DWORD unk2;
	/* 052 */   DWORD unk3;
	/* 056 */   DWORD dwFlags;
	/* 060 */   DWORD64 dwMasterKeyLen;
	/* 068 */   DWORD64 dwBackupKeyLen;
	/* 076 */   DWORD64 dwCredHistLen;
	/* 084 */   DWORD64 dwDomainKeyLen;
	/* 092 */   P_DPAPI_MASTERKEY MasterKey;
	/* 096 */   P_DPAPI_MASTERKEY BackupKey;
	/* 100 */   P_DPAPI_MASTERKEY_CREDHIST CredHist;
	/* 104 */   P_DPAPI_MASTERKEY_DOMAINKEY DomainKey;
} DPAPI_MASTERKEYS, * P_DPAPI_MASTERKEYS;


class MasterKey {

public:

	bool Decrypt(const void * memory, int dwMemory) {
		bool status = false;
		P_DPAPI_MASTERKEYS masterKeys = NULL;
		P_DPAPI_MASTERKEY masterKey = NULL;
		do {
			if (memory == NULL || dwMemory <= 0) {
				break;
			}
			// setting parameter
			masterKeys = (P_DPAPI_MASTERKEYS)new BYTE[sizeof(DPAPI_MASTERKEYS) + 1];
			memset(masterKeys, 0, sizeof(DPAPI_MASTERKEYS) + 1);
			memcpy(masterKeys, (char *)memory, sizeof(DPAPI_MASTERKEYS));
			if (masterKeys->dwMasterKeyLen > dwMemory) {
				break;
			}
			masterKey = (P_DPAPI_MASTERKEY)new char[masterKeys->dwMasterKeyLen + 1];
			memset(masterKey, 0, masterKeys->dwMasterKeyLen + 1);
			memcpy(masterKey, (char *)memory + FIELD_OFFSET(DPAPI_MASTERKEYS, MasterKey), masterKeys->dwMasterKeyLen);

			memcpy(m_salt, masterKey->salt, 16);
			m_iterations = masterKey->rounds;

			int dwMasterKey = masterKeys->dwMasterKeyLen - FIELD_OFFSET(DPAPI_MASTERKEY, pbKey);
			if (dwMasterKey < 80 || dwMasterKey >= dwMemory) {
				break;
			}
			m_masterKey.resize(dwMasterKey);
			memcpy(m_masterKey.data(), masterKey->pbKey, dwMasterKey);
			// decrypt master key
			std::string passHash = SSLHelper::sha1(m_password.data(), m_password.size());
			std::string sha1DerivedKey = SSLHelper::HMAC_SHA1(passHash.c_str(), SHA_DIGEST_LENGTH, m_sid.data(), m_sid.size());
			std::string HMACHash = SSLHelper::PBKDF2_SHA512(
				/*password*/ sha1DerivedKey.c_str(), 20,
				/*  salt  */ m_salt, 16,
				/* rounds */ m_iterations, 48);

			std::string key = HMACHash.substr(0, 32);
			std::string iv = HMACHash.substr(32, 16);

			std::string plain = SSLHelper::AesCBCDecrypt(m_masterKey.data(), dwMasterKey, key.c_str(), 32, iv.c_str());
			if (plain == "") {
				break;
			}
			status = MemoryVerify(plain.c_str(), dwMasterKey, sha1DerivedKey.c_str(), 20);
			if (status == true) {
				m_plainMasterKey.resize(dwMasterKey - 80);
				memcpy(m_plainMasterKey.data(), plain.c_str() + 80, dwMasterKey - 80);
			}
		} while (false);

		if (masterKeys != NULL) {
			delete[] masterKeys;
			masterKeys = NULL;
		}

		if (masterKey != NULL) {
			delete[] masterKey;
			masterKey = NULL;
		}

		return status;
	}

	void SetParameter(const std::string& password, const std::string& sid) {
		for (auto& it : password) {
			m_password.push_back(it);
			m_password.push_back(0);
		}
		for (auto& it : sid) {
			m_sid.push_back(it);
			m_sid.push_back(0);
		}
		m_sid.push_back(0);
		m_sid.push_back(0);
	}

	const std::vector<char>& GetMasterKey() {
		return m_plainMasterKey;
	}

	int GetMasterKeySize() const {
		return m_plainMasterKey.size();
	}

	explicit MasterKey() noexcept {
		m_iterations = 0;
		memset(m_salt, 0, 16);
	}

	~MasterKey() = default;

private:

	bool MemoryVerify(const void* masterKey, int szKey, const void* shaDerivedKey, int szShaKey) {
			bool status = false;
			if (m_masterKey.size() <= 0 || shaDerivedKey == NULL) {
				return false;
			}

			char salt[16] = { 0 };
			char savedHash[64] = { 0 };

			memcpy(salt, masterKey, 16);
			memcpy(savedHash, (char*)masterKey + 16, 64);

			std::string hmac1 = SSLHelper::HMAC_SHA512(shaDerivedKey, szShaKey, salt, 16);
			std::string hmac2 = SSLHelper::HMAC_SHA512(hmac1.c_str(), SHA512_DIGEST_LENGTH, (char*)masterKey + 80, szKey - 80);

			status = (memcmp(savedHash, hmac2.c_str(), SHA512_DIGEST_LENGTH) == 0);
			return status;
		}

private:
	// extern parameter
	std::vector<char> m_masterKey;
	std::vector<char> m_password;
	std::vector<char> m_sid;
	
	char m_salt[16];
	std::vector<char> m_plainMasterKey;

	int m_iterations;
};