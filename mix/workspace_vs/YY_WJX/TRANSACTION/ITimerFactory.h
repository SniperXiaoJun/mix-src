//-------------------------------------------------------------------------------------
// 文件名: InviteCT.h
// 创建人: Yan haicheng 
// 日  期: 2010-08-03
// 描  述: 头文件，定义Invite客户端事务类
// 版  本: 1.0
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
