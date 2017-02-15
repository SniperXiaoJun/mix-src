#include "NonInviteCT.h"
#include "../SIPProtocol/MsgFactory.h"

using namespace SIPTrans;

#ifdef MEMORY_TEST
#include "../Test/debug_new.h"
#endif

#ifdef DEBUG_RELEASE
#include "..\ManFile\LogFile.h"
CLogFile tlog;
#endif

CNonInviteCT::CNonInviteCT(INotify *pWorkers, ITimerFactory *pTimerFactory,
						   ISendData *pDataSender, IReceiveData *pDataReceiver, CSIPFunc *pSIPFunc)
						   : CTransaction(pWorkers, pTimerFactory, pDataSender, pDataReceiver, pSIPFunc)
{
	m_eState = NONINVITECT_TRYING;
	m_iTimerE = T1;
	m_pTimerE = NULL;
	m_pTimerF = NULL;
	m_pTimerK = NULL;
#ifdef DEBUG_RELEASE
	tlog.Open("\\Program Files\\Manager\\trans.txt", CFileOperation::modeAppendWrite);
#endif
}

CNonInviteCT::~CNonInviteCT(void)
{
#ifdef DEBUG_RELEASE
	tlog.Close();
#endif
}

//////////////////////////////////////////////////////////////////////
// void CNonInviteCT::handle_timeout(ETIMERTYPE eTimerType)
// 输入参数：
// ETIMERTYPE eTimerType ETIMERTYPE 类型的定时器类型
// 输出参数：
// 无
// 说明：
// 处理不同种类的到期的定时器
// 返回值：
// 无
// 创建人
// 2010-08-03 闫海成
//////////////////////////////////////////////////////////////////////
void CNonInviteCT::HandleTimeOut(ETIMERTYPE eTimerType)
{
	switch (eTimerType)
	{
	case NONInviteCT_E:
		TimerETimeOut();
		return;
	case NONInviteCT_F:
		TimerFTimeOut();
		return;
	case NONInviteCT_K:
		TimerKTimeOut();
		return;
	default:
		return;
	}
}

//////////////////////////////////////////////////////////////////////
// void CNonInviteCT::SetRequest(CSIPMsg *pSipMsg)
// 输入参数：
// CSIPMsg *pSipMsg ：CSIPMsg *型的SIP消息
// 输出参数：
// 无
// 说明：
// 处理从TU接收到的请求消息
// 返回值：
// 无
// 创建人
// 2010-08-03 闫海成
//////////////////////////////////////////////////////////////////////
int CNonInviteCT::SetRequest(const CUAPMsg &sipMsg)
{
	CMsgFactory myFactory(m_pSIPFunc);
	if (NONINVITECT_TRYING == m_eState)
	{
		// 拷贝SIP消息，并且解析
		delete m_pLastReqMsg;
		m_pLastReqMsg = myFactory.CreateMsg(sipMsg.GetMsgText(), sipMsg.GetMsgLen());
		if (0 != m_pLastReqMsg->ParseMsg())
		{
			return MsgErr;
		}

		m_pDataReceiver->ReceiveData(this);
		// 发送SIP消息
		if (ISendData::NoErr != m_pDataSender->SendData(m_pLastReqMsg->GetMsgText(),
			m_pLastReqMsg->GetMsgLen()))
		{
			m_eState = NONINVITECT_TERMINATED;
			return TransportErr;
		}
		else
		{
			// 启动定时器
			m_pTimerE = m_pTimerFactory->CreateTimer(NONInviteCT_E);
			m_pTimerF = m_pTimerFactory->CreateTimer(NONInviteCT_F);
			if (NULL != m_pTimerE && NULL != m_pTimerF)
			{
				m_pTimerE->Schedule(T1, this);
				m_pTimerF->Schedule(64 * T1, this);
				return NoErr;
			}
			else
			{
				return TimerErr;
			}
		}
	}
	else
	{
		return StateErr;
	}
}

//////////////////////////////////////////////////////////////////////
// void CNonInviteCT::SetResponse(CSIPMsg *pSipMsg)
// 输入参数：
// CSIPMsg *pSipMsg ：CSIPMsg *型的SIP消息
// 输出参数：
// 无
// 说明：
// 处理从TU接收到的响应消息
// 返回值：
// 无
// 创建人
// 2010-08-03 闫海成
//////////////////////////////////////////////////////////////////////
int CNonInviteCT::SetResponse(const CUAPMsg &sipMsg)
{
	switch (m_eState)
	{
	case NONINVITECT_TRYING :
	case NONINVITECT_PROCEEDING :
		ProceedingResponse(sipMsg);
		break;
	default:
		break;
	}

	return NoErr;
}

//////////////////////////////////////////////////////////////////////
// void CNonInviteCT::ProceedingResponse(CSIPMsg *pSipMsg)
// 输入参数：
// CSIPMsg *pSipMsg ：CSIPMsg *型的SIP消息
// 输出参数：
// 无
// 说明：
// 处理在Proceeding状态下接收到的响应消息
// 返回值：
// 无
// 创建人
// 2010-08-03 闫海成
//////////////////////////////////////////////////////////////////////
void CNonInviteCT::ProceedingResponse(const CUAPMsg &sipMsg)
{
#ifdef DEBUG_RELEASE
	tlog.LogString("CNonInviteCT::ProceedingResponse");
	tlog.Flush();
#endif
	int iResNum = atoi(sipMsg.GetField(RESPONSE_STATUSCODE).GetValueString());
	if (iResNum >= 100 && iResNum <= 199)
	{
		m_pDataReceiver->ReceiveData(this);
		m_eState = NONINVITECT_PROCEEDING;
		//将临时相应交给TU
		m_pSipWorker->NotifyMsg(sipMsg);		
	}
	else if (iResNum >= 200 && iResNum <= 799)
	{
		//将响应消息交给TU
#ifdef DEBUG_RELEASE
		tlog.LogString(sipMsg.GetField(VIA_BRANCH).GetValueString());
		tlog.Flush();
#endif
		m_pDataReceiver = NULL;
		m_eState = NONINVITECT_COMPLETED;
		m_pSipWorker->NotifyMsg(sipMsg);
		m_pTimerK = m_pTimerFactory->CreateTimer(NONInviteCT_K);
		if (NULL != m_pTimerK)
		{
			m_pTimerK->Schedule(T4, this);
		}
	}
}

//////////////////////////////////////////////////////////////////////
// int CNonInviteCT::TimerETimeOut(void)
// 输入参数：
// 无
// 输出参数：
// 无
// 说明：
// 处理定时器E到期后的相关操作
// 返回值：
// int型的返回值 ： 函数处理流程成功与否
// 创建人
// 2010-08-03 闫海成
//////////////////////////////////////////////////////////////////////
int CNonInviteCT::TimerETimeOut(void)
{
	if ((NONINVITECT_TRYING == m_eState || NONINVITECT_PROCEEDING == m_eState)
		&& NULL != m_pLastReqMsg)
	{
		m_pDataSender->SendData(m_pLastReqMsg->GetMsgText(), m_pLastReqMsg->GetMsgLen());
	}

	if (NONINVITECT_TRYING == m_eState)
	{
		m_iTimerE = T2 > m_iTimerE * 2 ? m_iTimerE * 2 : T2;
		m_pTimerE->Schedule(m_iTimerE, this);
	}
	else if (NONINVITECT_PROCEEDING == m_eState)
	{
		m_pTimerE->Schedule(T2, this);
	}

	return NoErr;
}

//////////////////////////////////////////////////////////////////////
// int CNonInviteCT::TimerFTimeOut(void)
// 输入参数：
// 无
// 输出参数：
// 无
// 说明：
// 处理定时器F到期后的相关操作
// 返回值：
// int型的返回值 ： 函数处理流程成功与否
// 创建人
// 2010-08-03 闫海成
//////////////////////////////////////////////////////////////////////
int CNonInviteCT::TimerFTimeOut(void)
{
	// 通知TU超时
	if (NONINVITECT_COMPLETED != m_eState
		&& NONINVITECT_TERMINATED != m_eState) 
	{
		m_pSipWorker->NotifyErr(TimeOutErr);

		m_eState = NONINVITECT_TERMINATED;
		if (NULL != m_pLastReqMsg)
		{
			// 通知事务结束
			m_pSipWorker->NotifyEndTrans(NONInviteCT, m_pLastReqMsg->GetField(
				VIA_BRANCH).GetValueString());
		}
	}

	return NoErr;
}

//////////////////////////////////////////////////////////////////////
// int CNonInviteCT::TimerKTimeOut(void)
// 输入参数：
// 无
// 输出参数：
// 无
// 说明：
// 处理定时器F到期后的相关操作
// 返回值：
// int型的返回值 ： 函数处理流程成功与否
// 创建人
// 2010-08-03 闫海成
//////////////////////////////////////////////////////////////////////
int CNonInviteCT::TimerKTimeOut(void)
{
	m_eState = NONINVITECT_TERMINATED;
	if (NULL != m_pLastReqMsg)
	{
		// 通知事务结束
		m_pSipWorker->NotifyEndTrans(NONInviteCT,
			m_pLastReqMsg->GetField(VIA_BRANCH).GetValueString());
	}

	return NoErr;
}

void CNonInviteCT::HandleError(void)
{
	m_pSipWorker->NotifyErr(TransportErr);

	m_eState = NONINVITECT_TERMINATED;
	if (NULL != m_pLastReqMsg)
	{
		// 通知事务结束
		m_pSipWorker->NotifyEndTrans(NONInviteCT,
			m_pLastReqMsg->GetField(VIA_BRANCH).GetValueString());
	}
}

void CNonInviteCT::CloseTrans(void)
{
	if (NULL != m_pDataReceiver)
	{
		m_pDataReceiver->ResetCallBack();
	}

	delete m_pTimerK;
	m_pTimerK = NULL;
	delete m_pTimerF;
	m_pTimerF = NULL;
	delete m_pTimerE;
	m_pTimerE = NULL;
}
