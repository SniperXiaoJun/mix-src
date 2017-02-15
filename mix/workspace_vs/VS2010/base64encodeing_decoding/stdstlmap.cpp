// VS2010.cpp : 定义控制台应用程序的入口点。
//
//#include <string>
//#include <map>
//
//using std::map;
//using std::string;
//
//typedef struct _SAA
//{
//	string str;
//	char cz[10];
//}SAA;
//
//
//int main__(int argc, char* argv[])
//{
//	SAA a1;
//
//	a1.str = "abc";
//	a1.cz[0] = 'a';
//	a1.cz[1] = 'a';
//	a1.cz[2] = 'a';
//	a1.cz[3] = 0;
//
//	SAA a2 = a1;
//
//	printf("%s %s", a2.str.c_str(), a2.cz);
//
//
//	map<string, string * > mapStringToSPointer;
//
//	mapStringToSPointer["abc"] = new string("abc");
//	mapStringToSPointer["abcd"] = new string("abcd");
//	mapStringToSPointer["abce"] = new string("abce");
//	mapStringToSPointer["abcf"] = new string("abcf");
//
//	map<string, string * >::iterator it =  mapStringToSPointer.begin();
//
//	while(it!= mapStringToSPointer.end())
//	{
//		printf("%s\n", it->second->c_str());
//		it++;
//	}
//
//	/*while( it != mapStringToSPointer.end())
//	{
//		delete it->second;
//
//		it = mapStringToSPointer.erase(it);
//	}
//
//	int count = mapStringToSPointer.size();
//
//	it = mapStringToSPointer.find("abc");
//
//	if(it == mapStringToSPointer.end())
//	{
//		printf("123\n");
//	}
//	else
//	{
//		printf("23\n");
//	}*/
//	return getchar();
//}
