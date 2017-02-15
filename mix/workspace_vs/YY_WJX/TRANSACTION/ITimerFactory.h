//-------------------------------------------------------------------------------------
// �ļ���: InviteCT.h
// ������: Yan haicheng 
// ��  ��: 2010-08-03
// ��  ��: ͷ�ļ�������Invite�ͻ���������
// ��  ��: 1.0
//-------------------------------------------------------------------------------------

#ifndef _ITIMERFACTORY_H__
#define _ITIMERFACTORY_H__

#include "ITimer.h"
#include "TransactionDll.h"

class ITimerFactory
{
public:
	virtual ITimer *CreateTimer(ETIMERTYPE eTimerType) = 0;
};

#endif
