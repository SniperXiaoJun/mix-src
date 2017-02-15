//-------------------------------------------------------------------------------------
// 
// 文件名: ITimer.h
// 
// 创建人: Yan haicheng 
// 
// 日  期: 2010-08-03
//
// 描  述: 头文件，定义定时器类
//
// 版  本: 1.0
// 
//-------------------------------------------------------------------------------------

#ifndef _ITIMER_H__
#define _ITIMER_H__

#include "ITimerCallBack.h"

class ITimer
{
public:
	virtual ~ITimer(){};
	//定时器单位为毫秒
	virtual int Schedule(int imsInterval, ITimerCallBack *pCallBack) = 0;
};

#endif
