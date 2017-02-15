//-------------------------------------------------------------------------------------
// �ļ���: ReceiveCallBack.h
// ������: Yan haicheng 
// ��  ��: 2010-08-03
// ��  ��: ͷ�ļ�������������ݻص���
// ��  ��: 1.0
//-------------------------------------------------------------------------------------

#ifndef _IRECEIVECALLBACK_HH
#define _IRECEIVECALLBACK_HH

#include "../Common/common.h"
typedef unsigned int u32;
class IReceiveCallBack
{
public:
	virtual void HandleReceiveData(const Byte *pMsg, u32 ulLen) = 0;
	virtual void HandleError(void) = 0;
};

#endif
