//-------------------------------------------------------------------------------------
// �ļ���: INotify.h
// ������: Yan haicheng 
// ��  ��: 2010-08-03
// ��  ��: ͷ�ļ�������֪ͨ�ϲ��INotify���࣬�ص��ӿ��в��ܳ��������ͶԵ��ûص��Ķ��������
// ��  ��: 1.0
//-------------------------------------------------------------------------------------

#ifndef _NOTIFY_H__
#define _NOTIFY_H__

#include "../UAPMsg/UAPMsg.h"
#include "TransactionDll.h"

class INotify
{
public:
	virtual void NotifyMsg(const CUAPMsg &sipMsg) = 0;
	virtual void NotifyErr(int iErr) = 0;
	virtual bool NotifyEndTrans(int iTransType, const string &strBranch) = 0;
};

#endif
