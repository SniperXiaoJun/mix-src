
#include "o_all_func_def.h"
#include "stdlib.h"
#include "string.h"
#include "stdio.h"


unsigned int OPF_Str2Bin(const char *pbIN,unsigned int uiINLen,unsigned char *pbOUT,unsigned int * puiOUTLen)
{
	int i;
	unsigned int sn_len = uiINLen / 2;

	if(sn_len > *puiOUTLen)
	{
		*puiOUTLen = sn_len;
		return -1;
	}

	*puiOUTLen = sn_len;

	if(0 == pbOUT)
	{
		
	}
	else
	{
		memset(pbOUT, 0,sn_len);
		for (i = 0; i < sn_len; i++) {
			pbOUT[i] += CHAR_TO_16(*(pbIN + i * 2)) * 16;
			pbOUT[i] += CHAR_TO_16(*(pbIN + i * 2 + 1));
		}
	}

	return 0;
}

unsigned int OPF_Bin2Str(const unsigned char *pbIN,unsigned int uiINLen,char *pbOUT,unsigned int * puiOUTLen)
{
	int i;
	unsigned int sn_len = uiINLen * 2;

	if(sn_len > *puiOUTLen)
	{
		*puiOUTLen = sn_len;
		return -1;
	}

	*puiOUTLen = sn_len;

	if(0 == pbOUT)
	{
		
	}
	else
	{
		for (i = 0; i < uiINLen; i++) {
			sprintf(pbOUT + 2 * i, "%02X", pbIN[i]);
		}
	}

	return 0;
}


// 添加已分配的内存指针到列表
unsigned int OPF_AddMallocedHandleNodeDataToLink(OPST_HANDLE_NODE * * ppstHeader, void * pvNodeData)
{
	OPST_HANDLE_NODE * ptr = NULL;

	if(!ppstHeader || !pvNodeData)
	{
		return -1;
	}

	ptr = (OPST_HANDLE_NODE *)malloc (sizeof(OPST_HANDLE_NODE));

	ptr->ptr_next = *ppstHeader;
	ptr->ptr_data = pvNodeData;

	*ppstHeader = ptr;

	return 0;
}

// 释放指定的指针内存所在列表的节点以及指针本身
unsigned int OPF_DelAndFreeHandleNodeDataFromLink(OPST_HANDLE_NODE * * ppstHeader,  void * pvNodeData)
{
	OPST_HANDLE_NODE * ptr = 0, * ptr2free = 0;

	if(!ppstHeader || !pvNodeData)
	{
		return -1;
	}

	ptr = * ppstHeader;

	if (!(*ppstHeader))
	{
		return -1;
	}

	// 头节点
	if (pvNodeData == ptr->ptr_data)
	{
		ptr2free = ptr;
		ptr = ptr->ptr_next;
		free(ptr2free);
		* ppstHeader = ptr;
	}
	else
	{
		while(ptr)
		{
			if (pvNodeData == ptr->ptr_next->ptr_data)
			{
				ptr2free = ptr->ptr_next;
				ptr->ptr_next = ptr2free->ptr_next;
				free(ptr2free->ptr_data);
				free(ptr2free);
			}
			ptr = ptr->ptr_next;
		}
	}

	return 0;
}


unsigned int OPF_CheckExistHandleNodeDataFromLink(OPST_HANDLE_NODE * * ppstHeader,  void * pvNodeData)
{
	OPST_HANDLE_NODE * ptr = 0;

	if(!ppstHeader || !pvNodeData)
	{
		return -1;
	}

	ptr = * ppstHeader;

	while(ptr)
	{
		if (ptr->ptr_data == pvNodeData)
		{
			return 0;
		}
		ptr = ptr->ptr_next;
	}

	return -1;
}

unsigned int OPF_ClearExistHandleNodeDataFromLink(OPST_HANDLE_NODE * * ppstHeader)
{
	while(* ppstHeader)
	{
		OPF_DelAndFreeHandleNodeDataFromLink(ppstHeader,  * ppstHeader);
	}

	return 0;
}

#if defined(UNICODE)

#include <windows.h>

// 二进制与HEX相互转换
unsigned int OPF_WStr2Bin(const wchar_t *pbIN, unsigned int uiINLen, unsigned char *pbOUT, unsigned int * puiOUTLen)
{
	unsigned int length = WideCharToMultiByte(CP_UTF8, 0, pbIN, uiINLen, NULL, 0, NULL, NULL);
	unsigned char * convert = NULL;
	unsigned int uiRet = -1;
	int i;
	unsigned int sn_len = uiINLen / 2;

	if (length != uiINLen)
	{
		uiRet = -1;
		goto err;
	}

	convert = (unsigned char *)malloc(length);

	WideCharToMultiByte(CP_UTF8, 0, pbIN, uiINLen, convert, length, NULL, NULL);


	if (sn_len > *puiOUTLen)
	{
		*puiOUTLen = sn_len;
		uiRet = -1;
		goto err;
	}

	*puiOUTLen = sn_len;

	if (0 == pbOUT)
	{

	}
	else
	{
		memset(pbOUT, 0, sn_len);
		for (i = 0; i < sn_len; i++) {
			pbOUT[i] += CHAR_TO_16(*(pbIN + i * 2)) * 16;
			pbOUT[i] += CHAR_TO_16(*(pbIN + i * 2 + 1));
		}
	}
	uiRet = 0;

err:
	if (NULL != convert)
	{
		free(convert);
	}

	return uiRet;

}
// 二进制与HEX相互转换
unsigned int OPF_Bin2WStr(const unsigned char *pbIN, unsigned int uiINLen, wchar_t *pbOUT, unsigned int * puiOUTLen)
{
	char * convert = NULL;
	unsigned int uiRet = -1;
	int i;

	unsigned int sn_len = uiINLen * 2;

	if (sn_len > *puiOUTLen)
	{
		*puiOUTLen = sn_len;
		uiRet = -1;
		goto err;
	}

	*puiOUTLen = sn_len;

	if (0 == pbOUT)
	{

	}
	else
	{
		convert = (char *)malloc(uiINLen * 2+2);

		for (i = 0; i < uiINLen; i++) {
			sprintf(convert + 2 * i, "%02X", pbIN[i]);
		}

		MultiByteToWideChar(CP_UTF8, 0, convert, uiINLen * 2, pbOUT, *puiOUTLen, NULL, NULL);
	}

	uiRet = 0;

err:
	if (NULL != convert)
	{
		free(convert);
	}

	return uiRet;
}

#endif