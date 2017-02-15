//-------------------------------------------------------------------------------------
// �ļ���: TransFactory.h
// ������: Yan haicheng 
// ��  ��: 2010-08-03
// ��  ��: ͷ�ļ����������񹤳���
// ��  ��: 1.0
//-------------------------------------------------------------------------------------

#ifndef _TRANSFACTORY_H__
#define _TRANSFACTORY_H__

#include "Transaction.h"
#include "TransactionDll.h"

class TRANSACTIONDLL_API CTransFactory
{
public:
	static CTransaction *CreateTrans(int iTransType, INotify *pWorkers,
		ITimerFactory *pTimerFactory, ISendData *pDataSender,
		IReceiveData *pDataReceiver, CSIPFunc *pSIPFunc);
};

#endif
