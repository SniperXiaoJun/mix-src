#include <stdio.h>

int str_sub(const char * strSrc, const char * strSub)
{
	int i = 0;

	for(;strSrc[i] == strSub[i] && strSrc[i] && strSub[i]; i++)
	{

	}

	if(strSub[i] == '\0')
	{
		return 0;
	}
	else
	{
		return 1;
	}
}

const char * my_strstr(const char * strSrc, const char * strSub)
{
	int i = 0;
	for(;strSrc[i]; i++)
	{
		if(str_sub(strSrc+i, strSub) == 0)
		{
			return strSrc+i;
		}
	}

	return NULL;
	
}

#define MIN(a,b) a<b?a:b

int main(int argc, char * argv)
{
	const char * p = my_strstr("abcd", "bcde");

	int i = 3; int j = 4;

	int k = 0? i++: ++j;

	k = MIN(5,4);

	return 0;
}