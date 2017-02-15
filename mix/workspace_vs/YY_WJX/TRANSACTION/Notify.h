//-------------------------------------------------------------------------------------
// 文件名: INotify.h
// 创建人: Yan haicheng 
// 日  期: 2010-08-03
// 描  述: 头文件，定义通知上层的INotify基类，回调接口中不能出现阻塞和对调用回调的对象的析构
// 版  本: 1.0
//-------------------------------------------------------------------------------------

#ifndef _NOTIFY_H__
#define _NOTIFY_H__

#include "../UAPMsg/UAPMsg.h"
#include "TransactionDll.h"

class INotify
{
public:
	virtual void NotifyMsg(const CUAPMsg &sipMsg) = 0;
	virtual void NotifyErr(int iErr) = 0;
	virtual bool NotifyEndTrans(int iTransType, const string &strBranch) = 0;
};

#endif
