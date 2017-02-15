#include "TransFactory.h"
#include "NonInviteCT.h"

using namespace SIPTrans;

#ifdef MEMORY_TEST
#include "../Test/debug_new.h"
#endif

CTransaction *CTransFactory::CreateTrans(int iTransType, INotify *pWorkers,
										 ITimerFactory *pTimerFactory,
										 ISendData *pDataSender,
										 IReceiveData *pDataReceiver, CSIPFunc *pSIPFunc)
{
	switch (iTransType)
	{
	case NONInviteCT :
		return new CNonInviteCT(pWorkers, pTimerFactory, pDataSender, pDataReceiver, pSIPFunc);
	default:
		return NULL;
	}
}
