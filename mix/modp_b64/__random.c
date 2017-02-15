#include "__random.h"

#include "string.h"
#include "time.h"
#include "stdlib.h"
#include "stdio.h"

void random_byte(unsigned char * a_data_value, unsigned int a_data_len)
{
	unsigned int i = 0; 

	if(NULL == a_data_value)
	{
		return;
	}

	srand((unsigned int)time(NULL) + (unsigned int)rand()); // 设定随机数种子

	//srand((unsigned int)time(NULL)); // 设定随机数种子

	for(i = 0; i < a_data_len; i++)
	{
		a_data_value[i] = rand()%255;
	}

	return;
}

void random_string(char * a_data_value, unsigned int a_data_len)
{
	unsigned int i = 0; 

	if(NULL == a_data_value)
	{
		return;
	}

	srand((unsigned int)time(NULL) + (unsigned int)rand()); // 设定随机数种子

	//srand((unsigned int)time(NULL)); // 设定随机数种子

	for(i = 0; i < a_data_len/2; i++)
	{
		sprintf(a_data_value + 2 * i,"%2X",rand()%255);
	}

	a_data_value[a_data_len] = '\0';

	return;
}