//-------------------------------------------------------------------------------------
// 文件名: timer.cpp
// 创建人: Li Bing
// 日  期: 2010-06-30
// 描  述: 实现CTimer类
// 版  本: 1.0
//-------------------------------------------------------------------------------------

#include "Timer.h"

void PASCAL GetCallback(UINT wTimerID, UINT msg,DWORD dwUser,DWORD dw1,DWORD dw2)
{
	CMyTimer::Callback((CMyTimer* )dwUser);
}

//////////////////////////////////////////////////////////////////////
// CTimer(ETIMERTYPE eTimerType)
// 输入参数：
// ETIMERTYPE eTimerType
// 输出参数：
// 无
// 说明：
// CTimer类构造函数
// 返回值：
// 无
// 创建人
// 2010-06-30 李冰
//////////////////////////////////////////////////////////////////////
CMyTimer::CMyTimer(ETIMERTYPE eTimerType)
{
	m_iAccuracy = 1;
	m_iMsSecond = 0;
	m_iTimerID = 0;
	m_bActive = false;
	m_bSingleShot = true;

	m_pTimerCallback = NULL;
	m_eTimerType = eTimerType;
}

//////////////////////////////////////////////////////////////////////
// ~CMyTimer()
// 输入参数：
// 无
// 输出参数：
// 无
// 说明：
// CMyTimer类析构函数
// 返回值：
// 无
// 创建人
// 2010-06-30 李冰
//////////////////////////////////////////////////////////////////////
CMyTimer::~CMyTimer()
{
	if(m_bActive)
	{
		CancelTimer();
	}
}

//////////////////////////////////////////////////////////////////////
// SetCallback(ITimerCallBack* pCallback)
// 输入参数：
// pCallback	指向ITimerCallBack接口的指针
// 输出参数：
// 无
// 说明：
// 设置回调对象
// 返回值：
// 无
// 创建人
// 2010-06-30 李冰
//////////////////////////////////////////////////////////////////////
void CMyTimer::SetCallback(ITimerCallBack *pCallback)
{
	m_pTimerCallback = pCallback;
}

//////////////////////////////////////////////////////////////////////
// SetTimer(Int32 iInterval)
// 输入参数：
// iInterval	设置的时间，以毫秒为单位
// 输出参数：
// 无
// 说明：
// 设置计时器
// 返回值：
// 无
// 创建人
// 2010-06-30 李冰
//////////////////////////////////////////////////////////////////////
void CMyTimer::SetTimer(Int32 iInterval)
{
	if(m_bActive)
	{
		CancelTimer();
	}
	if(m_bSingleShot)
	{
		if((m_iTimerID = timeSetEvent(iInterval,m_iAccuracy,(LPTIMECALLBACK)GetCallback,(DWORD)(this), TIME_ONESHOT)) == 0)
		{
			m_bActive = true;
		}
	}
	else
	{
		if((m_iTimerID = timeSetEvent(iInterval,m_iAccuracy,(LPTIMECALLBACK)GetCallback,(DWORD)(this), TIME_PERIODIC)) == 0)
		{
			m_bActive = true;
		}
	}

}

//////////////////////////////////////////////////////////////////////
// Callback()
// 输入参数：
// iInterval	设置的时间，以毫秒为单位
// 输出参数：
// 无
// 说明：
// 设置计时器
// 返回值：
// 无
// 创建人
// 2010-06-30 李冰
//////////////////////////////////////////////////////////////////////
void CMyTimer::Callback(CMyTimer * pTimer)
{
	if(NULL != pTimer)
	{
		if (pTimer->m_pTimerCallback != NULL)
		{
			pTimer->m_pTimerCallback->HandleTimeOut(pTimer->m_eTimerType);
		}
	}
}

//////////////////////////////////////////////////////////////////////
// CancelTimer()
// 输入参数：
// 无
// 输出参数：
// 无
// 说明：
// 取消计时器
// 返回值：
// 无
// 创建人
// 2010-06-30 李冰
//////////////////////////////////////////////////////////////////////
Bool CMyTimer::CancelTimer()
{
	if (m_bActive)
	{
		timeKillEvent(m_iTimerID);
		m_bActive = false;
		return true;
	}
	else
	{
		return false;
	}
}

//////////////////////////////////////////////////////////////////////
// SetTimerInHour(Int32 iInterval)
// 输入参数：
// iInterval	设置的时间，以小时为单位
// 输出参数：
// 无
// 说明：
// 设置计时器
// 返回值：
// 无
// 创建人
// 2010-06-30 李冰
//////////////////////////////////////////////////////////////////////
void CMyTimer::SetTimerInHour(Int32 iInterval)
{
	SetTimer(iInterval * 60 * 60 * 1000);
}

//////////////////////////////////////////////////////////////////////
// SetTimerInMinute(Int32 iInterval)
// 输入参数：
// iInterval	设置的时间，以分为单位
// 输出参数：
// 无
// 说明：
// 设置计时器
// 返回值：
// 无
// 创建人
// 2010-06-30 李冰
//////////////////////////////////////////////////////////////////////
void CMyTimer::SetTimerInMinute(Int32 iInterval)
{
	SetTimer(iInterval * 60 * 1000);
}

//////////////////////////////////////////////////////////////////////
// SetTimerInSecond(Int32 iInterval)
// 输入参数：
// iInterval	设置的时间，以秒为单位
// 输出参数：
// 无
// 说明：
// 设置计时器
// 返回值：
// 无
// 创建人
// 2010-06-30 李冰
//////////////////////////////////////////////////////////////////////
void CMyTimer::SetTimerInSecond(Int32 iInterval)
{
	SetTimer(iInterval * 1000);
}

void CMyTimer::SetTimerInMsec(Int32 iInterval)
{
	SetTimer(iInterval);
}

//////////////////////////////////////////////////////////////////////
// Sleep(UInt64 dwMilliseconds)
// 输入参数：
// dwMilliseconds	设置的时间，以毫秒为单位
// 输出参数：
// 无
// 说明：
// 设置等待，实现Sleep功能
// 返回值：
// 无
// 创建人
// 2010-09-07 李冰
//////////////////////////////////////////////////////////////////////
void CMyTimer::Sleep(UInt64 dwMilliseconds)
{
	::Sleep(dwMilliseconds);
}

Int32 CMyTimer::Schedule(Int32 imsInterval, ITimerCallBack *pCallBack)
{
	m_pTimerCallback = pCallBack;
	SetTimer(imsInterval);
	return 0;
}
