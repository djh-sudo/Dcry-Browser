#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include "C360.h"

using namespace std;

/*
* testing demo 1
* 
  string sid = SafeBrowserBookMark::GetUserSID();
  string guid = SafeBrowserBookMark::GetMachineGuid();
  SafeBrowserBookMark::Get360BookMark((LPWSTR)L"C:/Users/Administrator/AppData/Roaming/360se6/User Data/Default/360Bookmarks", (LPWSTR)L"C:/1.txt", sid, guid);
* 
* testing demo 2
* 
	FILE* fp = fopen("C:/Users/Administrator/AppData/Roaming/360se6/User Data/Default/360Bookmarks", "rb");
	if (fp == NULL) {
		return -1;
	}
	fseek(fp, 0, SEEK_END);
	DWORD dwSize = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	std::unique_ptr<char[]>buffer(new char[dwSize]);
	fread(buffer.get(), dwSize, 1, fp);
	SafeBrowserBookMark::Get360BookMark(buffer.get(), dwSize, (LPWSTR)L"C:/11.txt", sid, guid);
*
* testing demo 3
* 
    vector<Wrapper>res;
	SafeBrowserAutoSave::GetInfoFromSQL((LPWSTR)L"C:/Users/Administrator/AppData/Roaming/360se6/User Data/Default/apps/LoginAssis/assis2.db", guid, res);
* 
* testing demo 4
* 
    vector<History>his;
	string key = SafeBrowserBookMark::GetKey(sid, guid);
	SafeBrowserHistory::GetInfoFromSQL((LPWSTR)L"../test/360History", key, his);
* 
*/
int main() {

	string sid = SafeBrowserBookMark::GetUserSID();
	string guid = SafeBrowserBookMark::GetMachineGuid();

	SafeBrowserBookMark::Get360BookMark((LPWSTR)L"C:/Users/Administrator/AppData/Roaming/360se6/User Data/Default/360Bookmarks", (LPWSTR)L"C:/vfdv1.txt", sid, guid);
	
	vector<Wrapper>res;
	SafeBrowserAutoSave::GetInfoFromSQL((LPWSTR)L"C:/Users/Administrator/AppData/Roaming/360se6/User Data/Default/apps/LoginAssis/assis2.db", guid, res);
	for (auto& it : res) {
		cout << it.GetDomain() << " " << it.GetAccount() << " " << it.GetPassword() << endl;
	}

	vector<History>his;
	string key = SafeBrowserBookMark::GetKey(sid, guid);
	SafeBrowserHistory::GetInfoFromSQL((LPWSTR)L"../test/360History", key, his);

	return 0;
}