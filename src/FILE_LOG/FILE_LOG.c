/*
 * FILE_LOG.cpp
 *
 *  Created on: 2012-7-26
 *      Author: Administrator
 */
#include "FILE_LOG.h"
#include "stdio.h"
#include "string.h"
#include "stdlib.h"
#include <stdarg.h>

void FILE_READ(const char * dir, const char * fileName, unsigned char * byte, unsigned long * length)
{
	char path[BUFFER_LEN_1K] = {0};
	FILE * file = NULL;

	strcat(path,dir);
	strcat(path,fileName);

	* length = 0;

	file = fopen(path, "r+b");

	if (file)
	{
		* length = fread(byte, 1, BUFFER_LEN_1K * 4, file);

		fclose(file);
	}
}

void FILE_WRITE(const char * dir, const char * fileName, const unsigned char * byte, unsigned long length)
{
	char path[BUFFER_LEN_1K] = {0};
	FILE * file = NULL;

	strcat(path,dir);
	strcat(path,fileName);

	file = fopen(path, "w+b");

	if (file)
	{
		fwrite(byte, 1, length, file);

		fclose(file);
	}
}



#if FILE_LOG_TO_FILE

void FILE_LOG_STRING(const char * fileName, const char * cstring)
{
    FILE * file = fopen(fileName, "a+");

	if (file)
	{
		fwrite(cstring, 1, strlen(cstring), file);
		fwrite("\n",1,1,file);

		fclose(file);
	}
}

void FILE_LOG_HEX(const char * fileName, const unsigned char * byte, unsigned long length)
{
	long i = 0;
    FILE * file = fopen(fileName, "a+");

	//fwrite(byte, 1, length, file);
	//fwrite("\n",1,1,file);

	long dataLen = length * 2 + 1;

	char * dataValue = (char *)malloc(dataLen); 

	if (file)
	{
		for(i = 0; i < length; i++)
		{
			sprintf(dataValue + i * 2, "%02x", byte[i]);
		}

		fwrite(dataValue, 1, dataLen, file);
		fwrite("\n",1,1,file);

		free(dataValue);

		fclose(file);
	}
}

void FILE_LOG_NUMBER(const char * fileName, long number)
{
    FILE * file = fopen(fileName, "a+");
	
	char data[20] = {0};

	if (file)
	{
		sprintf(data, "%08x", number);

		fwrite(data, 1, strlen(data), file);
		fwrite("\n",1,1,file);

		fclose(file);
	}
}

void FILE_LOG_BYTE(const char * fileName, const unsigned char * byte, unsigned long length)
{
	FILE * file = fopen(fileName, "wb");

	if (file)
	{
		fwrite(byte,1,length, file);

		fclose(file);
	}
}

void FILE_LOG_FMT(const char * fileName,const char *format,...)
{
	FILE * file = fopen(fileName, "a+");
	va_list arglist;

	if (file)
	{
		va_start(arglist, format);
		vfprintf(file,format,arglist);
		fwrite("\n",1,1,file);

		fclose(file);
	}
}

#else

void FILE_LOG_STRING(const char * fileName, const char * cstring)
{

}

void FILE_LOG_HEX(const char * fileName, const unsigned char * byte, unsigned long length)
{
	
}

void FILE_LOG_NUMBER(const char * fileName, long number)
{

}

void FILE_LOG_BYTE(const char * fileName, const unsigned char * byte, unsigned long length)
{

}

void FILE_LOG_FMT(const char * fileName,const char *format,...)
{

}

#endif