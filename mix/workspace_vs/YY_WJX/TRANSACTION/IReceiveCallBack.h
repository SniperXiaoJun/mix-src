//-------------------------------------------------------------------------------------
// 文件名: ReceiveCallBack.h
// 创建人: Yan haicheng 
// 日  期: 2010-08-03
// 描  述: 头文件，定义接收数据回调类
// 版  本: 1.0
//-------------------------------------------------------------------------------------

#ifndef _IRECEIVECALLBACK_HH
#define _IRECEIVECALLBACK_HH

#include "../Common/common.h"
typedef unsigned int u32;
class IReceiveCallBack
{
public:
	virtual void HandleReceiveData(const Byte *pMsg, u32 ulLen) = 0;
	virtual void HandleError(void) = 0;
};

#endif
