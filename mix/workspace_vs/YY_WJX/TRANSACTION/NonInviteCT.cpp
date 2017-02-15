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
// ���������
// ETIMERTYPE eTimerType ETIMERTYPE ���͵Ķ�ʱ������
// ���������
// ��
// ˵����
// ����ͬ����ĵ��ڵĶ�ʱ��
// ����ֵ��
// ��
// ������
// 2010-08-03 �ƺ���
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
// ���������
// CSIPMsg *pSipMsg ��CSIPMsg *�͵�SIP��Ϣ
// ���������
// ��
// ˵����
// �����TU���յ���������Ϣ
// ����ֵ��
// ��
// ������
// 2010-08-03 �ƺ���
//////////////////////////////////////////////////////////////////////
int CNonInviteCT::SetRequest(const CUAPMsg &sipMsg)
{
	CMsgFactory myFactory(m_pSIPFunc);
	if (NONINVITECT_TRYING == m_eState)
	{
		// ����SIP��Ϣ�����ҽ���
		delete m_pLastReqMsg;
		m_pLastReqMsg = myFactory.CreateMsg(sipMsg.GetMsgText(), sipMsg.GetMsgLen());
		if (0 != m_pLastReqMsg->ParseMsg())
		{
			return MsgErr;
		}

		m_pDataReceiver->ReceiveData(this);
		// ����SIP��Ϣ
		if (ISendData::NoErr != m_pDataSender->SendData(m_pLastReqMsg->GetMsgText(),
			m_pLastReqMsg->GetMsgLen()))
		{
			m_eState = NONINVITECT_TERMINATED;
			return TransportErr;
		}
		else
		{
			// ������ʱ��
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
// ���������
// CSIPMsg *pSipMsg ��CSIPMsg *�͵�SIP��Ϣ
// ���������
// ��
// ˵����
// �����TU���յ�����Ӧ��Ϣ
// ����ֵ��
// ��
// ������
// 2010-08-03 �ƺ���
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
// ���������
// CSIPMsg *pSipMsg ��CSIPMsg *�͵�SIP��Ϣ
// ���������
// ��
// ˵����
// ������Proceeding״̬�½��յ�����Ӧ��Ϣ
// ����ֵ��
// ��
// ������
// 2010-08-03 �ƺ���
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
		//����ʱ��Ӧ����TU
		m_pSipWorker->NotifyMsg(sipMsg);		
	}
	else if (iResNum >= 200 && iResNum <= 799)
	{
		//����Ӧ��Ϣ����TU
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
// ���������
// ��
// ���������
// ��
// ˵����
// ����ʱ��E���ں����ز���
// ����ֵ��
// int�͵ķ���ֵ �� �����������̳ɹ����
// ������
// 2010-08-03 �ƺ���
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
// ���������
// ��
// ���������
// ��
// ˵����
// ����ʱ��F���ں����ز���
// ����ֵ��
// int�͵ķ���ֵ �� �����������̳ɹ����
// ������
// 2010-08-03 �ƺ���
//////////////////////////////////////////////////////////////////////
int CNonInviteCT::TimerFTimeOut(void)
{
	// ֪ͨTU��ʱ
	if (NONINVITECT_COMPLETED != m_eState
		&& NONINVITECT_TERMINATED != m_eState) 
	{
		m_pSipWorker->NotifyErr(TimeOutErr);

		m_eState = NONINVITECT_TERMINATED;
		if (NULL != m_pLastReqMsg)
		{
			// ֪ͨ�������
			m_pSipWorker->NotifyEndTrans(NONInviteCT, m_pLastReqMsg->GetField(
				VIA_BRANCH).GetValueString());
		}
	}

	return NoErr;
}

//////////////////////////////////////////////////////////////////////
// int CNonInviteCT::TimerKTimeOut(void)
// ���������
// ��
// ���������
// ��
// ˵����
// ����ʱ��F���ں����ز���
// ����ֵ��
// int�͵ķ���ֵ �� �����������̳ɹ����
// ������
// 2010-08-03 �ƺ���
//////////////////////////////////////////////////////////////////////
int CNonInviteCT::TimerKTimeOut(void)
{
	m_eState = NONINVITECT_TERMINATED;
	if (NULL != m_pLastReqMsg)
	{
		// ֪ͨ�������
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
		// ֪ͨ�������
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
