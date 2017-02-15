//-------------------------------------------------------------------------------------
// 文件名: Transaction.h
// 创建人: Yan haicheng 
// 日  期: 2010-08-03
// 描  述: 头文件，定义Transaction事务基类
// 版  本: 1.0
//-------------------------------------------------------------------------------------

#ifndef _TRANSACTION_H__
#define _TRANSACTION_H__

#include "../UAPMsg/UAPMsg.h"
#include "../SIPProtocol/SIPFunc.h"
#include "ITimerCallBack.h"
#include "IReceiveCallBack.h"
#include "Notify.h"
#include "ITimerFactory.h"
#include "ISendData.h"
#include "IReceiveData.h"
#include "TransactionDll.h"

namespace SIPTrans
{
	const int T1 = 500;         // 单位为ms
	const int T2 = 2000;		// 单位为ms
	const int T4 = 5000;		// 单位为ms

	enum ETransType
	{
		InviteST		= 0,
		InviteCT		= 1,
		NONInviteST		= 2,
		NONInviteCT		= 3
	};

	enum ETransErr
	{
		NoErr = 0,
		StateErr,
		MsgErr,
		TransportErr,//
		TimerErr,
		TimeOutErr   //
	};
}

class TRANSACTIONDLL_API CTransaction : public ITimerCallBack , public IReceiveCallBack
{
public:
	CTransaction(INotify *pWorkers, ITimerFactory *pTimerFactory,
		ISendData *pDataSender, IReceiveData *pDataReceiver, CSIPFunc *pSIPFunc)
	{
		m_pSipWorker = pWorkers;
		m_pTimerFactory = pTimerFactory;
		m_pDataSender = pDataSender;
		m_pDataReceiver = pDataReceiver;
		m_pSIPFunc = pSIPFunc;
		m_pLastReqMsg = NULL;
		m_pLastRespMsg = NULL;
	};

	virtual ~CTransaction(void);

	virtual int SetRequest(const CUAPMsg &sipMsg) = 0;
	virtual void CloseTrans(void) = 0;

	const CUAPMsg &GetMsg(void) const
	{
		return *m_pLastReqMsg;
	};

	void SetSipWorkersNotify(INotify *pWorkers)
	{
		m_pSipWorker = pWorkers;
	};

	void SetTimerFactory(ITimerFactory *pTimerFactory)
	{
		m_pTimerFactory = pTimerFactory;
	};

	void SetDataSender(ISendData *pDataSender)
	{
		m_pDataSender = pDataSender;
	};

	void SetDataReceiver(IReceiveData *pDataReceiver)
	{
		m_pDataReceiver = pDataReceiver;
	};

	void HandleReceiveData(const Byte *pMsg, u32 ulLen);
	void HandleError(void)
	{
		return;
	};

protected:
	virtual int SetResponse(const CUAPMsg &sipMsg) = 0;

protected:
	CUAPMsg *m_pLastReqMsg;
	CUAPMsg *m_pLastRespMsg;
	INotify *m_pSipWorker;
	ITimerFactory *m_pTimerFactory;
	ISendData *m_pDataSender;
	IReceiveData *m_pDataReceiver;
	CSIPFunc *m_pSIPFunc;
};

#endif
