/*
* CTimer.cpp
*
*  Created on: 2011-11-24
*      Author: Administrator
*/

#include "CTimer.h"

namespace TJU_CTIMER
{
	CTimer::CTimer(ETIMERTYPE eTimerType)
	{
		m_pTimerCallback = NULL;
		m_eTimerType = eTimerType;
		m_pTimer = NULL;
		m_bSingleShot = true;
	}

	CTimer::~CTimer()
	{
		if (m_pTimer != NULL)
		{
			if(m_pTimer->isRunning())
			{
				m_pTimer->stop();
			}
			delete m_pTimer;
			m_pTimer = NULL;
		}
		
		m_pTimerCallback = NULL;
	}

	void CTimer::SetCallback(ITimerCallBack *pCallback)
	{
		m_pTimerCallback = pCallback;
	}

	void CTimer::SetTimer(Int32 iInterval)
	{
		if (m_pTimer != NULL)
		{
			if(m_pTimer->isRunning())
			{
				m_pTimer->stop();
			}
			delete m_pTimer;
			m_pTimer = NULL;
		}

		m_pTimer = new LRTimer();

		m_pTimer->setCallbackProc(Callback ,this);
		m_pTimer->start(iInterval);
	}

	void CTimer::Callback(VOID* ptr)
	{
		if (((TJU_CTIMER::CTimer*)ptr)->m_pTimerCallback != NULL)
		{
			((TJU_CTIMER::CTimer*)ptr)->m_pTimerCallback->HandleTimeOut(((TJU_CTIMER::CTimer*)ptr)->m_eTimerType);
			if(((TJU_CTIMER::CTimer*)ptr)->m_bSingleShot)
			{
				((TJU_CTIMER::CTimer*)ptr)->m_pTimer->stop();
			}
		}
	}

	Bool CTimer::CancelTimer()
	{
		if (m_pTimer != NULL)
		{
			if(m_pTimer->isRunning())
			{
				m_pTimer->stop();
			}
			delete m_pTimer;
			m_pTimer = NULL;
			return TRUE;
		}

		return FALSE;
	}

	void CTimer::SetTimerInHour(Int32 iInterval)
	{
		SetTimer(iInterval * 60 * 60 * 1000);
	}

	void CTimer::SetTimerInMinute(Int32 iInterval)
	{
		SetTimer(iInterval * 60 * 1000);
	}

	void CTimer::SetTimerInSecond(Int32 iInterval)
	{
		SetTimer(iInterval * 1000);
	}

	void CTimer::SetTimerInMsec(Int32 iInterval)
	{
		SetTimer(iInterval);
	}

	void CTimer::Sleep(UInt64 dwMilliseconds)
	{
		::Sleep(dwMilliseconds);
	}

	Int32 CTimer::Schedule(Int32 imsInterval, ITimerCallBack *pCallBack)
	{
		m_pTimerCallback = pCallBack;
		SetTimer(imsInterval);
		return 0;
	}
}
