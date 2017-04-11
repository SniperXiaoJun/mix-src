

#include "encode_switch.h"
#include <windows.h>

string GBKToUTF8(const std::string& strGBK) 
{ 
	string strOutUTF8 = ""; 
	wchar_t * str1;
	int n = MultiByteToWideChar(CP_ACP, 0, strGBK.c_str(), -1, NULL, 0); 
	str1 = new wchar_t[n]; 
	MultiByteToWideChar(CP_ACP, 0, strGBK.c_str(), -1, str1, n); n = WideCharToMultiByte(CP_UTF8, 0, str1, -1, NULL, 0, NULL, NULL);
	char * str2 = new char[n]; 
	WideCharToMultiByte(CP_UTF8, 0, str1, -1, str2, n, NULL, NULL); 
	strOutUTF8 = str2; 
	delete[]str1; 
	str1 = NULL; 
	delete[]str2;
	str2 = NULL; 
	return strOutUTF8;
}

string UTF8ToGBK(const std::string& strUTF8) 
{ 
	int len = MultiByteToWideChar(CP_UTF8, 0, strUTF8.c_str(), -1, NULL, 0);
	wchar_t * wszGBK = new wchar_t[len + 1]; 
	
	memset(wszGBK, 0, len * 2 + 2); 
	MultiByteToWideChar(CP_UTF8, 0, (LPCSTR)strUTF8.c_str(), -1, wszGBK, len);

	len = WideCharToMultiByte(CP_ACP, 0, wszGBK, -1, NULL, 0, NULL, NULL); 
	char *szGBK = new char[len + 1];
	memset(szGBK, 0, len + 1); 
	WideCharToMultiByte(CP_ACP,0, wszGBK, -1, szGBK, len, NULL, NULL); //strUTF8 = szGBK; 
	std::string strTemp(szGBK); 
	delete[]szGBK; 
	delete[]wszGBK; 
	return strTemp; 
}


// Convert a wide Unicode string to an UTF8 string
std::string utf8_encode(const std::wstring &wstr) {
	// when got a empty wstring, vs2010 will break on an asserting: string 
	// substring out of range
	if (wstr.size() == 0) return "";
	int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
	std::string strTo(size_needed, 0);
	WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
	return strTo;
}

// Convert an UTF8 string to a wide Unicode String
std::wstring utf8_decode(const std::string &str) {
	if (str.size() == 0) return L"";
	int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
	std::wstring wstrTo(size_needed, 0);
	MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
	return wstrTo;
}