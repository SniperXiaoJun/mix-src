#include <stdio.h>
#include <string.h>
#include <time.h>

char * __strrev(char * str)
{
	int len = strlen(str);
	int i = 0;
	int j = len-1;

	for(i = 0; i < len -1; i++, len--)
	{
		str[i] = str[i]^str[len-1];
		str[len-1] = str[i]^str[len-1];
		str[i] = str[i]^str[len-1];
	}
	return str;
} 

int main()
{
	char str[] = "Hello World";
	printf("%s", __strrev(str));
	return 0;
}

