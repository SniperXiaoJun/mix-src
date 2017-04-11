
#include <string>

using namespace std;


string GBKToUTF8(const std::string& strGBK);

string UTF8ToGBK(const std::string& strUTF8);

std::string utf8_encode(const std::wstring &wstr);
std::wstring utf8_decode(const std::string &str);