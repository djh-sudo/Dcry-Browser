#pragma once
#include <string>
#include <iostream>
#include <vector>
#include <unordered_map>
#include <codecvt>
#include <Windows.h>
#include "sqlite3.h"
#include "CipherHelper.h"

/*
* DingTalk db file is stored at
* C:/Users/%username%/AppData/Roaming/DingTalk/uid_v2/DBFiles/dingtalk.db
* uid is the seed of key!!
* this key will be used to encrypted database(DB)
* Encrypted parameter:
* KEY = (md5(uid)).encode() AES-128
* page size is 0x1000(4096)
*/

#define PAGE_SIZE      0x1000
#define TABLE_MESSAGE "tbmsg_"
/*
* user profile is at table tbuser_profile_v2
*/

class UserProfile {

public:

	explicit UserProfile() noexcept {
		m_uid = "";
		m_nick = L"";
		m_city = L"";
		m_mobile = "";
		m_gender = ' ';
	}
	
	explicit UserProfile(const char* uid,
		        const wchar_t* nick,
				char gender,
		        const wchar_t* city,
		        const char* mobile) {
		m_uid = std::string(uid);
		m_nick = std::wstring(nick);
		m_city = std::wstring(city);
		m_mobile = std::string(mobile);
		m_gender = gender;
	}

	virtual ~UserProfile() = default;

	std::string GetUid() const {
		return m_uid;
	}

	std::wstring GetNick() const  {
		return m_nick;
	}

	std::wstring GetCity() const {
		return m_city;
	}

	std::string GetMobile() const {
		return m_mobile;
	}

	char GetGender() const {
		return m_gender;
	}

private:
	std::string m_uid;
	std::wstring m_nick;
	std::wstring m_city;
	std::string m_mobile;
	char m_gender;
};

/*
* Conversation is at table tbconversation
*/
class Conversation {

public:

	explicit Conversation() {
		m_cid = "";
		m_title = L"";
		m_isGroup = false;
	}

	virtual ~Conversation() = default;

	std::string GetCid() const {
		return m_cid;
	}
	
	std::wstring GetTitle() const {
		return m_title;
	}

	bool GetIsGroup() const {
		return m_isGroup;
	}

	Conversation(const char *cid,
		         const wchar_t * title,
				 char type = '1') {
		m_cid = std::string(cid);
		m_title = std::wstring(title);
		m_isGroup = (type == '2');
	}

private:
	std::string m_cid;
	std::wstring m_title;
	bool m_isGroup;
};

/*
* Message is at table tbmsg
*/
class Message {

public:

	explicit Message() noexcept {
		m_jsonContent = L"";
		m_sendId = "";
		m_cid = "";
	}

	explicit Message(const char * cid, const char* id, const char * content) {
		std::wstring_convert<std::codecvt_utf8<wchar_t>>converter;
		m_sendId = std::string(id);
		m_cid = std::string(cid);
		m_jsonContent = converter.from_bytes(content);
	}

	virtual ~Message() = default;
	
	std::wstring GetContent() const noexcept {
		return m_jsonContent;
	}

	std::string GetSendId() const noexcept {
		return m_sendId;
	}

	std::string GetCid() const noexcept {
		return m_cid;
	}

private:
	std::wstring m_jsonContent;
	std::string m_sendId;
	std::string m_cid;
};

class DingTalk {

public:

	static bool SavePlainDB(LPWSTR dbPath, std::string uid, LPWSTR savePath) {
		if (dbPath == NULL || uid == "" || savePath == NULL) {
			return false;
		}

		std::string key = SSLHelper::md5(uid, uid.size());
		key = SSLHelper::EncodeHex(key, 16);
		bool status = false;
		do {
			FILE* fp = _wfopen(dbPath, L"rb");
			if (fp == NULL) {
				break;
			}
			fseek(fp, 0, SEEK_END);
			int dwSize = ftell(fp);
			if (dwSize % PAGE_SIZE != 0) {
				break;
			}
			fseek(fp, 0, SEEK_SET);
			std::unique_ptr<unsigned char[]>buffer = std::make_unique<unsigned char[]>(dwSize);
			if (buffer == NULL) {
				fclose(fp);
				fp = NULL;
				break;
			}
			fread(buffer.get(), 1, dwSize, fp);
			if (fp != NULL) {
				fclose(fp);
				fp = NULL;
			}
			int blockCount = dwSize / PAGE_SIZE;
			FILE* out = _wfopen(savePath, L"ab+");
			if (out == NULL) {
				break;
			}
			for (int i = 0; i < blockCount; ++i) {
				std::string plain = SSLHelper::AesDecrypt(buffer.get() + (i << 12), PAGE_SIZE, (unsigned char *)key.c_str());
				fwrite(plain.c_str(), 1, PAGE_SIZE, out);
			}
			fclose(out);
			out = NULL;
			
			status = true;
		} while (false);
		return status;
	}

	static bool GetUserProfile(LPWSTR dbPath, std::vector<UserProfile>&res) {
		if (dbPath == NULL) {
			return false;
		}
		sqlite3* db = NULL;
		int status = SQLITE_OK;
		do {
			status = sqlite3_open16(dbPath, &db);
			if (status != SQLITE_OK) {
				break;
			}
			// SELECT uid,nick,gender,city,mobile FROM tbuser_profile_v2
			sqlite3_stmt* stat = NULL;
			const wchar_t* szSql = L"SELECT uid,nick,gender,city,mobile FROM tbuser_profile_v2";
			status = sqlite3_prepare16(db, szSql, lstrlenW(szSql) * 2, &stat, 0);
			if (status != SQLITE_OK) {
				break;
			}
			while (SQLITE_ROW == sqlite3_step(stat)) {
				res.push_back(UserProfile(
					(const char *)sqlite3_column_text(stat, 0),
					(const wchar_t *)sqlite3_column_text16(stat, 1),
					(const char)sqlite3_column_text(stat, 2)[0],
					(const wchar_t*)sqlite3_column_text16(stat, 3),
					(const char *)sqlite3_column_text(stat, 4)));
			}
			sqlite3_close(db);
		} while (false);

		return status == SQLITE_OK;
	}

	static bool GetConversation(LPWSTR dbPath, std::vector<Conversation>& res) {
		if (dbPath == NULL) {
			return false;
		}
		sqlite3* db = NULL;
		int status = SQLITE_OK;
		do {
			status = sqlite3_open16(dbPath, &db);
			if (status != SQLITE_OK) {
				break;
			}
			// SELECT cid,type,title FROM tbconversation;
			sqlite3_stmt* stat = NULL;
			const wchar_t* szSql = L"SELECT cid,type,title FROM tbconversation;";
			status = sqlite3_prepare16(db, szSql, lstrlenW(szSql) * 2, &stat, 0);
			if (status != SQLITE_OK) {
				break;
			}
			while (SQLITE_ROW == sqlite3_step(stat)) {
				res.push_back(Conversation(
					(const char *)sqlite3_column_text(stat, 0),
					(const wchar_t *)sqlite3_column_text16(stat, 2),
					(const char)sqlite3_column_text(stat, 1)[0]
				));
			}
			sqlite3_close(db);
		} while (false);

		return status == SQLITE_OK;
	}

	static bool GetUserMessage(LPWSTR dbPath,std::unordered_map<std::string,std::vector<Message>>&res) {
		if (dbPath == NULL) {
			return false;
		}
		sqlite3* db = NULL;
		int status = SQLITE_OK;
		do {
			status = sqlite3_open16(dbPath, &db);
			if (status != SQLITE_OK) {
				break;
			}
			// SELECT name FROM sqlite_sequence;
			sqlite3_stmt* stat = NULL;
			const wchar_t* szSql = L"SELECT name FROM sqlite_sequence;";
			status = sqlite3_prepare16(db, szSql, lstrlenW(szSql) * 2, &stat, 0);
			if (status != SQLITE_OK) {
				break;
			}
			std::vector<std::string>tb;
			while (SQLITE_ROW == sqlite3_step(stat)) {
				std::string tbName = std::string((char *)sqlite3_column_text(stat, 0));
				if (tbName.substr(0, 6) == TABLE_MESSAGE) {
					tb.emplace_back(tbName);
				}
				else {
					continue;
				}
			}
			for (auto& it : tb) {
				// SELECT senderId,content FROM [table name]
				std::string szSql1 = "SELECT cid,senderId,content FROM " + it;
				stat = NULL;
				status = sqlite3_prepare(db, szSql1.c_str(), szSql1.size(), &stat, 0);
				if (status != SQLITE_OK) {
					break;
				}
				res[it] = std::vector<Message>();
				while (SQLITE_ROW == sqlite3_step(stat)) {
					res[it].push_back(Message((const char*)sqlite3_column_text(stat, 0), (const char *)sqlite3_column_text(stat, 1), (const char *)sqlite3_column_text(stat, 2)));
				}
			}	
			sqlite3_close(db);
		} while (false);

		return status == SQLITE_OK;
	}

	explicit DingTalk() = default;
	
	virtual ~DingTalk() = default;

private:
};