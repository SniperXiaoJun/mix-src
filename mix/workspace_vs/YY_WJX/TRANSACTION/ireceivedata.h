//-------------------------------------------------------------------------------------
// 文件名: IReceiveData.h
// 创建人: Yan haicheng 
// 日  期: 2010-08-03
// 描  述: 头文件，定义接收数据抽象类
// 版  本: 1.0
//-------------------------------------------------------------------------------------

#ifndef _IRECEIVEDATA_H__
#define _IRECEIVEDATA_H__

#include "IReceiveCallBack.h"
#include "TransactionDll.h"

class IReceiveData
{
public:
	virtual int ReceiveData(IReceiveCallBack *pCallBack) = 0;
	virtual void ResetCallBack() = 0;
};

#endif
