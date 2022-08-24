#include <cstdlib>
#include <memory>
#include <iostream>
#include <string>
#include "Analysis.h"


using namespace std;


int main() {

	string chromeBlob = "RFBBUEkBAAAA0Iyd3wEV0RGMegDAT8KX6wEAAADUO/VAmoIoS5Ktwq2LmE43AAAAAAIAAAAAABBmAAAAAQAAIAAAABnhgGq1cxkeLHab55WWdgYCFt3TF09bs2LkLp+EVJDyAAAAAA6AAAAAAgAAIAAAAD9jP02RJhcR7CJ5+EB4YvGCZQEHgsjTkCeh0tz1fu0tMAAAAB0VYry5qr1flRsDjnmGHOqF7vNi7F570mOUP+bHKhIA0WcK3n0e5OCjqzPIuD4wiEAAAACKQ0vXFLubspAYCEUVk/LP5sFnqTnKsDA+D/Wue5KqwqKoPSZoPgfGL9Jd4V/rjPiJub6Ryp7GUbTZNIZCy3aG";
	string sid = Chrome::GetUserSID();
	string login = "123456";
	Chrome chrome;
	// step 1 Init
	chrome.Init(chromeBlob, sid, login);
	string guid = chrome.GetGuid();
	// step 2 read Master key file
	string filePath = "C:/Users/Administrator/AppData/Roaming/Microsoft/Protect/" + sid + "/" + guid;
	FILE* fp = fopen(filePath.c_str(), "rb");
	if (fp == NULL) {
		return -1;
	}
	fseek(fp, 0, SEEK_END);
	int fileSize = ftell(fp);
	unique_ptr<char[]>buffer(new char[fileSize]);
	fseek(fp, 0, SEEK_SET);
	fread(buffer.get(), fileSize, 1, fp);
	bool status = chrome.DecryptKey(buffer.get(), fileSize);
	if (status == false) {
		return -1;
	}
	// step 3 query login id/psw from SQL
	std::vector<UserInfo> res;
	status = chrome.GetUserInfoFromSQL((LPWSTR)L"../test/Login Data", res);
	if (status == false) {
		return -1;
	}
	// step 4 query cookie from SQL
	std::vector<UserCookie> cookie;
	status = chrome.GetUserCookieFromSQL((LPWSTR)L"../test/Cookies", cookie);
	if (status == false) {
		return -1;
	}
	return 0;
}
