#include <stdio.h>

int main()
{
	if(remove("1.txt"))
	{
		printf("Could not delete the file %s \n","1.txt");
	}
	else
	{ 
		printf("OK \n");
	}
	return 0;
} 