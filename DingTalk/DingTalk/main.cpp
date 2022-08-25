#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include "Analysis.h"

using namespace std;


int main() {
	// step 1 Decrypt database(DB)
	DingTalk::SavePlainDB((LPWSTR)L"../test/dingtalk.db", "********", (LPWSTR)L"ding.db");
	// step 2 get user profile from table tbuser_profile_v2
	vector<UserProfile>profile;
	DingTalk::GetUserProfile((LPWSTR)L"ding.db", profile);
	// step 3 get conversation
	vector<Conversation>conversation;
	DingTalk::GetConversation((LPWSTR)L"ding.db", conversation);
	// step 4 get message
	unordered_map<string, vector<Message>>message;
	DingTalk::GetUserMessage((LPWSTR)L"ding.db", message);
	// Ending
	return 0;
}