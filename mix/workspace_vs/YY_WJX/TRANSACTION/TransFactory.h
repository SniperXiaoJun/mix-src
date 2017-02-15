//-------------------------------------------------------------------------------------
// 文件名: TransFactory.h
// 创建人: Yan haicheng 
// 日  期: 2010-08-03
// 描  述: 头文件，定义事务工厂类
// 版  本: 1.0
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
