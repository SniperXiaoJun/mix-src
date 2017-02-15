//-------------------------------------------------------------------------------------
// 文件名: NonInviteCT.h
// 创建人: Yan haicheng 
// 日  期: 2010-08-03
// 描  述: 头文件，定义NonInvite客户端事务类
// 版  本: 1.0
//-------------------------------------------------------------------------------------

#ifndef _NONINVITECT_H__
#define _NONINVITECT_H__

#include "Transaction.h"

enum ENONINVITECT_STATE
{
	NONINVITECT_TRYING			= 0x01,
	NONINVITECT_PROCEEDING		= 0x02,
	NONINVITECT_COMPLETED		= 0x03,
	NONINVITECT_TERMINATED		= 0x04
};

class CNonInviteCT : public CTransaction
{
public:
	CNonInviteCT(INotify *pWorkers, ITimerFactory *pTimerFactory,
		ISendData *pDataSender, IReceiveData *pDataReceiver, CSIPFunc *pSIPFunc);
	~CNonInviteCT(void);

	int SetRequest(const CUAPMsg &sipMsg);
	virtual void CloseTrans(void);
	void HandleTimeOut(ETIMERTYPE eTimerType);
	void HandleError(void);

protected:
	int SetResponse(const CUAPMsg &sipMsg);

private:
	int TimerETimeOut(void);
	int TimerFTimeOut(void);
	int TimerKTimeOut(void);
	void ProceedingResponse(const CUAPMsg &sipMsg);
	
	ENONINVITECT_STATE m_eState;
	int m_iTimerE;
	ITimer *m_pTimerE;
	ITimer *m_pTimerF;
	ITimer *m_pTimerK;
};

#endif
