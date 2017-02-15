//-------------------------------------------------------------------------------------
// �ļ���: IReceiveData.h
// ������: Yan haicheng 
// ��  ��: 2010-08-03
// ��  ��: ͷ�ļ�������������ݳ�����
// ��  ��: 1.0
//-------------------------------------------------------------------------------------

#ifndef _IRECEIVEDATA_H__
#define _IRECEIVEDATA_H__

#include "IReceiveCallBack.h"
#include "TransactionDll.h"

class IReceiveData
{
public:
	virtual int ReceiveData(IReceiveCallBack *pCallBack) = 0;
	virtual void ResetCallBack() = 0;
};

#endif
