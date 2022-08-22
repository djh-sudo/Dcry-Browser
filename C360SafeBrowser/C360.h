#pragma once
/*
* 360 safe browser bookmark decrypt!
* user data stored at
* C:/Users/%username%/AppData/Roaming/360se6/User Data/Default/360Bookmarks
* browser version: 13.1.6140.0
*/

#include <memory>
#include <string>
#include <vector>
#include <codecvt>
#include <Windows.h>
#include "CipherHelper.h"
#include "sqlite3.h"


#pragma comment(lib, "libsqlite3.lib")

typedef unsigned __int64 QWORD;

static BYTE stub[] = {
			0x1f, 0x7d, 0x14, 0x89, 0x4d, 0xb8, 0x8b, 0x4d, 0x18, 0x89, 0x45, 0xbc, 0x89, 0x7d, 0xb0, 0x89,
			0x4d, 0xac, 0x89, 0x5d, 0xd0, 0x89, 0x5d, 0xc8, 0x88, 0x5d, 0xd7, 0x88, 0x5d, 0xc0, 0x3b, 0xfb,
			0x0f, 0x84, 0x77, 0x93, 0x03, 0x00, 0x89, 0x90, 0x8b, 0x4e, 0x10, 0xf7, 0x41, 0x08, 0x00, 0x40,
			0x00, 0x00, 0x0f, 0x84, 0x6f, 0x93, 0x03, 0x00, 0xf7, 0x46, 0x68, 0x00, 0x01, 0x00, 0x00, 0x0f,
			0x85, 0x58, 0xcc, 0x03, 0x00, 0xf6, 0x05, 0xa0, 0x03, 0xfe, 0x7f, 0x01, 0xbf, 0x00, 0x01, 0x00,
			0x02, 0x0f, 0x85, 0x4f, 0x96, 0x03, 0x00, 0x89, 0x5d, 0xd8, 0x85, 0x7e, 0x68, 0x0f, 0x85, 0x8b,
			0x96, 0x03, 0x00, 0x38, 0x5e, 0x02, 0x0f, 0x85, 0xea, 0x96, 0xcc, 0x00, 0xeb, 0x1d, 0x39, 0x5d,
			0xc8, 0x0f, 0x85, 0x3b, 0x97, 0x03, 0x00, 0x8b, 0x45, 0xd8, 0x8b, 0x4d, 0xfc, 0x5f, 0x5e, 0x33,
			0x10, 0x00, 0x00, 0x00, 0x57, 0x00, 0x44, 0x00, 0x4c, 0x00, 0x32, 0x00, 0x30, 0x00, 0x31, 0x00,
			0x36, 0x00, 0x00, 0x00 };

static const char aes_key[] = { 0x63, 0x66, 0x36, 0x36, 0x66, 0x62, 0x35, 0x38, 0x66, 0x35, 0x63, 0x61, 0x33, 0x34, 0x38, 0x35 };

class SafeBrowserBookMark {

public:

	static std::string GetMachineGuid() {
		std::string machineguid = "";
		HKEY hKey;
		DWORD ret;
		// \HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography
		LPWSTR lpszSubKey = (LPWSTR)L"SOFTWARE\\Microsoft\\Cryptography";
		DWORD maxValueDataLen = MAX_PATH;
		DWORD dwType = REG_SZ;
		std::unique_ptr<BYTE[]>lpData(new BYTE[maxValueDataLen]);

		do {
			ret = RegOpenKeyExW(HKEY_LOCAL_MACHINE, lpszSubKey, 0, KEY_READ | KEY_WOW64_64KEY, &hKey);
			if (ret != ERROR_SUCCESS) {
				break;
			}

			ret = RegQueryValueEx(hKey, L"MachineGuid", NULL, &dwType, lpData.get(), &maxValueDataLen);
			if (ret != ERROR_SUCCESS) {
				break;
			}
			int iLen = WideCharToMultiByte(CP_ACP, NULL, (LPCWCH)lpData.get(), -1, NULL, 0, NULL, FALSE);
			machineguid.resize(iLen - 1);
			WideCharToMultiByte(CP_OEMCP, NULL, (LPCWCH)lpData.get(), -1, (LPSTR)machineguid.c_str(), iLen, NULL, FALSE);

		} while (false);

		RegCloseKey(hKey);
		return machineguid;
	}

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
		for (int i = 0; i < subAuthorities; ++i){
			dwSID += sprintf(sid + dwSID, "-%lu", *GetSidSubAuthority(userSID, i));
		}
		return std::string(sid);
	}

	static bool Get360BookMark(LPWSTR filePath, LPWSTR savePath, std::string sid, std::string guid) {
		SafeBrowserBookMark bookmark;
		bool status = false;
		do {
			status = bookmark.Init(filePath, savePath, sid, guid);
			if (status == false) {
				break;
			}
			status = bookmark.Get360BookMarkByFile();
		} while (false);
		return status;
	}

	static bool Get360BookMark(const void* memory, int size, LPWSTR savePath, std::string sid, std::string guid) {
		SafeBrowserBookMark bookmark;
		bool status = false;
		do {
			status = bookmark.Init(memory, size, savePath, sid, guid);
			if (status == false) {
				break;
			}
			status = bookmark.Get360BookMarkByMemory();
		} while (false);
		return status;
	}

	bool Init(LPWSTR filePath, LPWSTR savePath, std::string sid, std::string guid) {
		if (sid == "" || guid == "") {
			return false;
		}
		m_sid = sid;
		m_machineGuid = guid;
		if (filePath == NULL) {
			return false;
		}
		m_filePath = filePath;
		if (savePath == NULL) {
			return false;
		}
		m_hFile = CreateFileW(savePath, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (m_hFile == INVALID_HANDLE_VALUE) {
			return false;
		}
		m_memoryBuffer = NULL;
		m_dwMemoryBuffer = 0;
		return true;
	}

	bool Init(const void* memory, int size, LPWSTR savePath, std::string sid, std::string guid) {
		if (memory == NULL || size <= 0 || size >= INT_MAX) {
			return false;
		}
		if (sid == "" || guid == "") {
			return false;
		}
		m_hFile = CreateFileW(savePath, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (m_hFile == INVALID_HANDLE_VALUE) {
			return false;
		}
		m_filePath = L"";
		m_memoryBuffer = (char *)memory;
		m_dwMemoryBuffer = size;
		m_sid = sid;
		m_machineGuid = guid;
		return true;
	}

	void Unit() {
		m_machineGuid = "";
		m_sid = "";
		m_filePath = L"";
		if (m_hFile != INVALID_HANDLE_VALUE) {
			::CloseHandle(m_hFile);
			m_hFile = INVALID_HANDLE_VALUE;
		}
		if (m_memoryBuffer != NULL) {
			m_memoryBuffer = NULL;
			m_dwMemoryBuffer = 0;
		}
	}

	bool Get360BookMarkByFile() {
		std::string key = GetBookMarkKey();
		HANDLE m_hBookMark = ::CreateFileW(m_filePath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

		if (INVALID_HANDLE_VALUE == m_hBookMark) {
			return false;
		}
		DWORD dwNumByte = 0;
		std::unique_ptr<BYTE[]>buffer(new BYTE[4096]);

		std::string iv = "33mhsq0uwgzblwdo";
		std::string bookmarks = "";
		std::string src = "";
		while (true) {
			memset(buffer.get(), 0, 4096);
			if (::ReadFile(m_hBookMark, buffer.get(), 4096, &dwNumByte, NULL) == FALSE) {
				break;
			}
			if (dwNumByte <= 0) {
				break;
			}
			src += std::string((char*)buffer.get(), dwNumByte);
		}
		int dwDecode = src.size();
		std::string cipher = SSLHelper::Base64Decode(src, dwDecode);
		cipher = cipher.substr(4);
		bookmarks = SSLHelper::AesCBCDecrypt(cipher, dwDecode - 4, key, 32, iv);
		// unpack
		int padding = bookmarks.back();
		if (padding > 0 && padding <= 0x10) {
			while (bookmarks.back() == padding) {
				bookmarks.pop_back();
			}
		}
		::CloseHandle(m_hBookMark);

		// decode
		std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
		std::wstring data = converter.from_bytes(bookmarks);

		// write to file
		::WriteFile(m_hFile, data.c_str(), data.size() * sizeof(wchar_t), &dwNumByte, NULL);

		return true;
	}

	bool Get360BookMarkByMemory() {
		std::string key = GetBookMarkKey();
		std::string iv = "33mhsq0uwgzblwdo";
		std::string bookmarks = "";
		int dwDecode = m_dwMemoryBuffer;
		std::string cipher = SSLHelper::Base64Decode(m_memoryBuffer, dwDecode);
		cipher = cipher.substr(4);
		bookmarks = SSLHelper::AesCBCDecrypt(cipher, dwDecode - 4, key, 32, iv);
		// unpack
		int padding = bookmarks.back();
		if (padding > 0 && padding <= 0x10) {
			while (bookmarks.back() == padding) {
				bookmarks.pop_back();
			}
		}
		// decode
		std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
		std::wstring data = converter.from_bytes(bookmarks);

		// write to file
		DWORD dwNumByte = 0;
		::WriteFile(m_hFile, data.c_str(), data.size() * sizeof(wchar_t), &dwNumByte, NULL);

		return true;
	}

	explicit SafeBrowserBookMark() noexcept {
		m_hFile = INVALID_HANDLE_VALUE;
		m_memoryBuffer = NULL;
		m_dwMemoryBuffer = 0;
		m_machineGuid = "";
		m_sid = "";
		m_filePath = L"";
	}

	~SafeBrowserBookMark() {
		Unit();
	}

private:
	// Cryptographic
	inline DWORD _ZIMU(DWORD d1, DWORD d2) noexcept {
		return d1 * d2;
	}

	inline DWORD _ZOO3(DWORD d1, DWORD d2) noexcept {
		return _ZIMU(d2, d1 >> 16);
	}

	inline DWORD _ZOO1(DWORD d1, DWORD d2, DWORD d3) noexcept {
		return _ZIMU(d2, d1) - _ZOO3(d1, d3);
	}

	inline DWORD _ZOO2(DWORD d1, DWORD d2, DWORD d3) noexcept {
		return _ZIMU(d2, d1) + _ZOO3(d1, d3);
	}

	inline DWORD Rand(DWORD seed) noexcept {
		return 0x343fd * seed + 0x269ec3;
	}

	QWORD CS64_WordSwap(CONST DWORD* src, DWORD iChNum, DWORD iMd51, DWORD iMd52) {
		DWORD dwMD50 = (iMd51 | 1) + 0x69FB0000;
		DWORD dwMD51 = (iMd52 | 1) + 0x13DB0000;

		DWORD dwRet0 = 0;
		DWORD dwRet1 = 0;

		DWORD i = 0;
		DWORD dwTemp00 = 0;
		DWORD dwTemp01 = 0;
		DWORD dwTemp02 = 0;
		DWORD dwTemp03 = 0;
		DWORD dwTemp04 = 0;
		DWORD dwTemp05 = 0;
		DWORD dwTemp06 = 0;
		DWORD dwTemp07 = 0;

		while (i < iChNum) {
			dwTemp00 = dwRet0;
			if (i < iChNum)
				dwTemp00 += src[i];
			dwTemp01 = _ZOO1(dwTemp00, dwMD50, 0x10FA9605);
			dwTemp02 = _ZOO2(dwTemp01, 0x79F8A395, 0x689B6B9F);
			dwTemp03 = _ZOO1(dwTemp02, 0xEA970001, 0x3C101569);
			++i;

			dwTemp04 = dwTemp03;
			if (i < iChNum)
				dwTemp04 += src[i];
			dwTemp05 = _ZOO1(dwTemp04, dwMD51, 0x3CE8EC25);
			dwTemp06 = _ZOO1(dwTemp05, 0x59C3AF2D, 0x2232E0F1);
			dwTemp07 = _ZOO2(dwTemp06, 0x1EC90001, 0x35BD1EC9);
			++i;
			dwRet0 = dwTemp07;
			dwRet1 = dwTemp03 + dwRet0 + dwRet1;
		}

		QWORD res = 0;
		DWORD* ptr = (DWORD*)&res;
		*ptr = dwRet0; ptr++;
		*ptr = dwRet1;
		return res;
	}

	QWORD CS64_Reversible(CONST DWORD* src, DWORD iChNum, DWORD iMd51, DWORD iMd52) {
		DWORD dwMD50 = iMd51 | 1;
		DWORD dwMD51 = iMd52 | 1;

		DWORD dwRet0 = 0;
		DWORD dwRet1 = 0;

		DWORD i = 0;
		DWORD dwTemp00 = 0, dwTemp01 = 0, dwTemp02 = 0;
		DWORD dwTemp03 = 0, dwTemp04 = 0, dwTemp05 = 0;
		DWORD dwTemp06 = 0, dwTemp07 = 0, dwTemp08 = 0;
		DWORD dwTemp09 = 0, dwTemp10 = 0, dwTemp11 = 0;

		while (i < iChNum) {
			dwTemp00 = dwRet0;
			if (i < iChNum)
				dwTemp00 += src[i];
			dwTemp01 = dwMD50 * dwTemp00;
			dwTemp02 = _ZOO1(dwTemp01, 0xB1110000, 0x30674EEF);
			dwTemp03 = _ZOO1(dwTemp02, 0x5B9F0000, 0x78F7A461);
			dwTemp04 = _ZOO2(dwTemp03, 0xB96D0000, 0x12CEB96D);
			dwTemp05 = _ZOO2(dwTemp04, 0x1D830000, 0x257E1D83);
			++i;

			dwTemp06 = dwTemp05;
			if (i < iChNum)
				dwTemp06 += src[i];
			dwTemp07 = dwMD51 * dwTemp06;
			dwTemp08 = _ZOO1(dwTemp07, 0x16F50000, 0x5D8BE90B);
			dwTemp09 = _ZOO1(dwTemp08, 0x96FF0000, 0x2C7C6901);
			dwTemp10 = _ZOO2(dwTemp09, 0x2B890000, 0x7C932B89);
			dwTemp11 = _ZOO1(dwTemp10, 0x9F690000, 0x405B6097);
			++i;

			dwRet0 = dwTemp11;
			dwRet1 = dwTemp05 + dwRet0 + dwRet1;
		}
		QWORD res = 0;
		DWORD* ptr = (DWORD*)&res;
		*ptr = dwRet0; ptr++;
		*ptr = dwRet1;
		return res;
	}

	QWORD _360Hash(CONST DWORD* src, DWORD dwWsLen, DWORD iMd51, DWORD iMd52) {
		DWORD dwCount = dwWsLen >> 2;
		if (dwCount & 1)
			--dwCount;
		QWORD r1 = CS64_WordSwap(src, dwCount, iMd51, iMd52);
		QWORD r2 = CS64_Reversible(src, dwCount, iMd51, iMd52);
		return r1 ^ r2;
	}

	void UrlEncode(CONST PBYTE data, DWORD szLen, CONST PBYTE dataOut, DWORD& szOutLen) {
		// "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-.:/"
		DWORD out = 0;
		szOutLen = szLen;
		char tmp[4] = { 0 };
		for (int i = 0; i < szLen; ++i) {
			if (data[i] == ' ') {
				*(dataOut + out) = '+'; ++out;
			}
			else if (data[i] < 0x2e || data[i] > 'z') {
				memset(tmp, 0, 4);
				sprintf(tmp, "%%%02x", data[i]);
				*(dataOut + out) = tmp[0]; ++out;
				*(dataOut + out) = tmp[1]; ++out;
				*(dataOut + out) = tmp[2]; ++out;
				szOutLen += 2;
			}
			else if ((data[i] >= '-' && data[i] <= ':') ||
				     (data[i] >= 'a' && data[i] <= 'z') ||
				     data[i] >= 'A' && data[i] <= 'Z') {
				*(dataOut + out) = data[i];
				++out;
			}
			else {
				memset(tmp, 0, 4);
				sprintf(tmp, "%%%02x", data[i]);
				*(dataOut + out) = tmp[0]; ++out;
				*(dataOut + out) = tmp[1]; ++out;
				*(dataOut + out) = tmp[2]; ++out;
				szOutLen += 2;
			}
		}
		return;
	}

	void RandEnc(PBYTE data, DWORD size, CONST PBYTE dataOut, DWORD mseed = 0x8000402b) {
		DWORD out = 0;
		*((DWORD*)dataOut) = mseed;
		out += 4;

		DWORD temp00 = size;
		temp00 >>= 2;
		DWORD count = 0;
		DWORD seed = mseed;
		PBYTE ptr = NULL;

		while (temp00 > 0) {
			seed = Rand(seed);
			ptr = (PBYTE)&seed;
			for (int i = 0; i < 4; ++i) {
				*(dataOut + out) = (data[count + i] ^ ptr[i]);
				++out;
			}
			count += 4;
			temp00 -= 1;
		}
		seed = Rand(seed);
		ptr = (PBYTE)&seed;
		for (int i = 0; i < (size & 3); ++i) {
			*(dataOut + out) = data[count + i] ^ ptr[i];
			++out;
		}
		return;
	}

	void TeaEncrypt(PBYTE iv, PBYTE key, CONST PBYTE dataOut) {
		DWORD out = 0;
		DWORD seed = 0x9e3779b9;
		DWORD v4 = *(DWORD*)iv;
		DWORD v5 = *((DWORD*)(iv + 4));
		DWORD key0 = *(DWORD*)key;
		DWORD key1 = *((DWORD*)(key + 4));
		DWORD key2 = *((DWORD*)(key + 8));
		DWORD key3 = *((DWORD*)(key + 12));
		for (int i = 0; i < 8; ++i) {
			v4 += (key0 + (v5 << 4)) ^ (v5 + seed) ^ (key1 + (v5 >> 5));
			v5 += (key2 + (v4 << 4)) ^ (v4 + seed) ^ (key3 + (v4 >> 5));
			seed -= 0x61c88647;
		}

		*((DWORD*)(dataOut + out)) = v4;
		out += 4;
		*((DWORD*)(dataOut + out)) = v5;
		return;
	}

	bool Tea360(PBYTE pbData, DWORD szpbData, CONST PBYTE out, DWORD size = 0x80) {
		std::unique_ptr<BYTE[]>data(new BYTE[size]);
		memcpy(data.get(), pbData, szpbData);
		if (size > szpbData) {
			memset(data.get() + szpbData, 0, size - szpbData);
		}

		BYTE keys[16] = { 0 };
		memcpy(keys, data.get(), 16);

		for (int i = 0; i < 16; ++i) {
			TeaEncrypt(data.get() + i * 8, keys, out + i * 8);
		}
		return true;
	}

	std::string GetBookMarkKey() {
		std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
		// step 1 padding stub
		DWORD stub_len = sizeof(stub);
		// step 2 concatenate payload one
		BYTE payload_one[512] = { 0 };
		memcpy(payload_one, stub, stub_len);

		DWORD offset = stub_len;
		DWORD str_len = m_sid.size() << 1;
		std::wstring sid = converter.from_bytes(m_sid);
		memcpy(payload_one + offset, sid.c_str(), str_len);
		offset += str_len;

		wchar_t tmp[] = L"/?";
		memcpy(payload_one + offset, tmp, 4);
		offset += 4;

		str_len = m_machineGuid.size() << 1;
		std::wstring machineGuid = converter.from_bytes(m_machineGuid);
		memcpy(payload_one + offset, machineGuid.c_str(), str_len);
		offset += str_len;

		// calculate MD5
		std::string md5_payload_one = SSLHelper::md5(payload_one, offset);

		DWORD* ptr = (DWORD*)md5_payload_one.c_str();
		DWORD a = *ptr;
		DWORD b = *(ptr + 1);

		QWORD mhashbs = _360Hash((DWORD*)payload_one, offset, a, b);

		// step 3 urls encode
		std::string encode = SSLHelper::Base64Encode((char *)&mhashbs, 8);
		DWORD dwMhash_encbs = encode.size();
		std::unique_ptr<BYTE[]>mhash_encbs(new BYTE[dwMhash_encbs * 2]);

		UrlEncode((PBYTE)(char*)encode.c_str(), dwMhash_encbs, mhash_encbs.get(), dwMhash_encbs);

		// step 4 concatenate payload-two
		std::unique_ptr<BYTE[]>payload_two(new BYTE[1024]);
		DWORD magic_number = 1;

		memcpy(payload_two.get(), &magic_number, 4);
		offset = 4;
		memcpy(payload_two.get() + offset, &stub_len, 4);
		offset += 4;

		memcpy(payload_two.get() + offset, stub, stub_len);
		offset += stub_len;

		magic_number = 2;
		memcpy(payload_two.get() + offset, &magic_number, 4);
		offset += 4;

		memcpy(payload_two.get() + offset, &dwMhash_encbs, 4);
		offset += 4;

		memcpy(payload_two.get() + offset, mhash_encbs.get(), dwMhash_encbs);
		offset += dwMhash_encbs;

		// step 5 rand enc
		std::unique_ptr<BYTE[]>randenc_bs(new BYTE[offset + 8]);
		RandEnc(payload_two.get(), offset, randenc_bs.get());

		std::string tmp_bs = SSLHelper::md5(randenc_bs.get(), offset + 4);
		std::string binascii_tmp_bs = SSLHelper::EncodeHex(tmp_bs, 16);

		// step 6 Tea 360
		std::unique_ptr<BYTE[]>tea360(new BYTE[192]);
		// x923 padding 0
		memset(tea360.get(), 0, 192);
		Tea360((PBYTE)binascii_tmp_bs.c_str(), 32, tea360.get());

		// step 7
		std::string key_bs = SSLHelper::md5(tea360.get(), 192);
		return SSLHelper::EncodeHex(key_bs, 16);
	}

	private:
		std::string m_machineGuid;
		std::string m_sid;

		HANDLE m_hFile;
		std::wstring m_filePath;

		char* m_memoryBuffer;
		DWORD m_dwMemoryBuffer;
};

/*
* 360 auto save file
* user data stored at
* C:/Users/Administrator/AppData/Roaming/360se6/User Data/Default/apps/LoginAssis/assis2.db
* This is encrypted db
* which key is Machine GUID from Regs [\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography]
*/
class Wrapper {
public:
	explicit Wrapper() noexcept {}

	explicit Wrapper(std::string domain, std::string account, std::string enc_password) noexcept {
		this->m_domain = domain;
		this->m_account = account;
		this->enc_password = enc_password;
	}

	~Wrapper() {}
private:
	std::string m_domain;
	std::string m_account;
	std::string enc_password;
};

class SafeBrowserAutoSave {

public:
	
	bool Init(LPWSTR dbfilePath, std::string guid, std::vector<Wrapper>& res) noexcept  {
		if (dbfilePath == NULL) {
			return false;
		}
		if (guid == "") {
			return false;
		}
		m_guid = guid;
		sqlite3* db = NULL;
		int status = SQLITE_OK;
		do {
			status = sqlite3_open16(dbfilePath, &db);
			if (status != SQLITE_OK) {
				break;
			}
			status = sqlite3_key(db, m_guid.c_str(), m_guid.size());
			if (status != SQLITE_OK) {
				break;
			}
			// select domain, username, password from tb_account;
			sqlite3_stmt* stat = NULL;
			const wchar_t* szSql = L"select domain, username, password from tb_account;";
			status = sqlite3_prepare16(db, szSql, lstrlenW(szSql) * 2, &stat, 0);
			if (status != SQLITE_OK) {
				break;
			}
			while (SQLITE_ROW == sqlite3_step(stat)) {
				std::string urls = std::string((const char*)sqlite3_column_text(stat, 0));
				std::string name = std::string((const char*)sqlite3_column_text(stat, 1));
				std::string password = std::string((const char*)sqlite3_column_text(stat, 2));
				password = DecryptPassword(password);
				res.push_back(Wrapper(urls, name, password));
			}
			
		} while (false);
		 return status == SQLITE_OK;
	}
	
	void Uint() noexcept {
		m_dbPath = L"";
		m_guid = "";
	}
	
	static void GetInfoFromSQL(LPWSTR dbfilePath, std::string guid, std::vector<Wrapper>&res) {
		SafeBrowserAutoSave autoSave;
		autoSave.Init(dbfilePath, guid, res);
		autoSave.Uint();
	}

	explicit SafeBrowserAutoSave() = default;
	
	~SafeBrowserAutoSave() {
		Uint();
	}
	
private:

	std::string DecryptPassword(std::string encPsw) {
		int size = encPsw.size() - 14;
		if (size <= 0) {
			return "";
		}
		std::string decodePassword = SSLHelper::Base64Decode(encPsw.substr(14), size);
		// AES-ECB-128
		std::string buffer = SSLHelper::AesECBDecrypt(decodePassword, size, aes_key, 16);
		std::string tempstr = "";

		if (buffer[0] == '\x01') {
			for (int j = 2; j < buffer.size(); j += 1) {
				if (j % 2 != 1)
					tempstr.append(1, buffer[j]);
				else
					continue;
			}
		}

		if (buffer[0] == '\x02') {
			for (int j = 1; j < buffer.size(); j += 1) {
				if (j % 2 == 1)
					tempstr.append(1, buffer[j]);
				else
					continue;
			}
		}

		return tempstr;
	}	

private:
	std::wstring m_dbPath;
	std::string m_guid;
};