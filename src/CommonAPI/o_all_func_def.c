
#include "o_all_func_def.h"
#include "stdlib.h"
#include "string.h"
#include "stdio.h"


unsigned long OPF_Str2Bin(const char *pbIN,unsigned long ulINLen,unsigned char *pbOUT,unsigned long * pulOUTLen)
{
	long i;
	unsigned long sn_len = ulINLen / 2;

	if(sn_len > *pulOUTLen)
	{
		*pulOUTLen = sn_len;
		return -1;
	}

	*pulOUTLen = sn_len;

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

unsigned long OPF_Bin2Str(const unsigned char *pbIN,unsigned long ulINLen,char *pbOUT,unsigned long * pulOUTLen)
{
	long i;
	unsigned long sn_len = ulINLen * 2;

	if(sn_len > *pulOUTLen)
	{
		*pulOUTLen = sn_len;
		return -1;
	}

	*pulOUTLen = sn_len;

	if(0 == pbOUT)
	{
		
	}
	else
	{
		for (i = 0; i < ulINLen; i++) {
			sprintf(pbOUT + 2 * i, "%02X", pbIN[i]);
		}
	}

	return 0;
}


// ����ѷ�����ڴ�ָ�뵽�б�
unsigned long OPF_AddMallocedHandleNodeDataToLink(OPST_HANDLE_NODE * * ppstHeader, void * pvNodeData)
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

// �ͷ�ָ����ָ���ڴ������б�Ľڵ��Լ�ָ�뱾��
unsigned long OPF_DelAndFreeHandleNodeDataFromLink(OPST_HANDLE_NODE * * ppstHeader,  void * pvNodeData)
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

	// ͷ�ڵ�
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


unsigned long OPF_CheckExistHandleNodeDataFromLink(OPST_HANDLE_NODE * * ppstHeader,  void * pvNodeData)
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

unsigned long OPF_ClearExistHandleNodeDataFromLink(OPST_HANDLE_NODE * * ppstHeader)
{
	while(* ppstHeader)
	{
		OPF_DelAndFreeHandleNodeDataFromLink(ppstHeader,  * ppstHeader);
	}

	return 0;
}