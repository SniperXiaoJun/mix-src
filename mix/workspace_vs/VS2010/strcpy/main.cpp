

#include <stdio.h>


char * my_strcpy(char * strdest, const char * strsrc)
{
	char * ptr = strdest;
	while(*strdest++ = *strsrc++)
	{

	}

	return ptr;
}

char * my_strcat(char * strdest, const char * strsrc)
{
	char * ptr = strdest;

	while( *strdest)
	{
		strdest++;
	}

	while(*strdest++ = * strsrc++)
	{

	}

	return ptr;
}

#include <string.h>

int iEqualSub(const char * strSrc, const char * strSub)
{
	int i = 0;

	for(;(strSrc[i] == strSub[i] 
		|| (strSrc[i] - strSub[i] == 'A' - 'a' && strSrc[i] >= 'A' && strSrc[i] <= 'Z') 
		|| (strSrc[i] - strSub[i] == 'a' - 'A' && strSrc[i] >= 'a' && strSrc[i] <= 'z')) 
		&& strSrc[i] && strSub[i]
		; i++)
	{

	}

	if(strSub[i] == '\0')
	{
		return 0;
	}
	else
	{
		return -1;
	}
}

int iFindSubStr(const char *szContent,const char *szPattern)
{
	int i = 0;

	if(NULL == szContent || NULL == szPattern)
	{
		return -1;
	}

	for(;szContent[i]; i++)
	{
		if(iEqualSub(szContent+i, szPattern) == 0)
		{
			return i;
		}
	}

	return -1;
}

#include <vector>
#include <string>

using namespace std;
int Tokenize(const string& str,const string& delimiters,vector<string>* tokens) 
//str is the input string. delimiters is the delimiting characters. tokens contains the vector of split words.
//For example, str=¡±abc,def,ghi¡±, delimiters is ¡°,¡±, the returned vector contains three words: 
//¡°abc¡±, ¡°def¡±, ¡°ghi¡±. 
{
    tokens->clear();
    int start = str.find_first_not_of(delimiters);
    while (start != string::npos) 
    {
    		int end = str.find_first_of(delimiters, start+1);
    		if (end == string::npos) 
					//if(start != str.length())
	{
		tokens->push_back(str.substr(start, end - start));
		break;
	}
    tokens->push_back(str.substr(start, end - start));
    start = str.find_first_not_of(delimiters, end + 1);
    }



return tokens->size();
}

int main()
{
	char sz[20] = "";

	vector<string> ve;

	int f = Tokenize(string(sz), string(","), &ve);



	my_strcpy(sz, "abcd Ef");

	int j = iFindSubStr(sz, NULL);

	strcpy(sz+1, sz);

	my_strcat(sz, "abcd");
	return 0;
}

#define m 9;
#define n 10;

int map[m][n];
int GetShortestPath(int xStart,int yStart,int xEnd,int yEnd) 
{
    if(xStart  ==  xEnd && yStart == yEnd)
    {
		return 0;
    }

}