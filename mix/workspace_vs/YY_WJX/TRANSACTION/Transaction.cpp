#include <iostream>
using namespace std;

#include "Transaction.h"
#include "../SIPProtocol/MsgFactory.h"

#ifdef MEMORY_TEST
#include "../Test/debug_new.h"
#endif

CTransaction::~CTransaction()
{
	delete m_pLastReqMsg;
	m_pLastReqMsg = NULL;
};

//////////////////////////////////////////////////////////////////////
// void CTransaction::handle_receive_data()
// ���������
// ��
// ���������
// ��
// ˵����
// �����첽��������
// ����ֵ��
// ��
// ������
// 2010-08-03 �ƺ���
//////////////////////////////////////////////////////////////////////
void CTransaction::HandleReceiveData(const Byte *pMsg, u32 ulLen)
{
	CMsgFactory myFactory(m_pSIPFunc);
	CUAPMsg *pSipMsg = myFactory.CreateMsg(pMsg, ulLen);
	int iFlag = pSipMsg->ParseMsg();
	string strLastBran = m_pLastReqMsg->GetField(VIA_BRANCH).GetValueString();
	string strNewBran = pSipMsg->GetField(VIA_BRANCH).GetValueString();
	if (m_pLastReqMsg != NULL && (strLastBran != strNewBran))
	{
		m_pDataReceiver->ReceiveData(this);	
		delete pSipMsg;
		pSipMsg = NULL;	
		return;
	}

	if (0 == iFlag)
	{
		SetResponse(*pSipMsg);
	}

	delete pSipMsg;
	pSipMsg = NULL;
}
