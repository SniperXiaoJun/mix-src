//-------------------------------------------------------------------------------------
// �ļ���: timer.cpp
// ������: Li Bing
// ��  ��: 2010-06-30
// ��  ��: ʵ��CTimer��
// ��  ��: 1.0
//-------------------------------------------------------------------------------------

#include "Timer.h"

void PASCAL GetCallback(UINT wTimerID, UINT msg,DWORD dwUser,DWORD dw1,DWORD dw2)
{
	CMyTimer::Callback((CMyTimer* )dwUser);
}

//////////////////////////////////////////////////////////////////////
// CTimer(ETIMERTYPE eTimerType)
// ���������
// ETIMERTYPE eTimerType
// ���������
// ��
// ˵����
// CTimer�๹�캯��
// ����ֵ��
// ��
// ������
// 2010-06-30 ���
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
// ���������
// ��
// ���������
// ��
// ˵����
// CMyTimer����������
// ����ֵ��
// ��
// ������
// 2010-06-30 ���
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
// ���������
// pCallback	ָ��ITimerCallBack�ӿڵ�ָ��
// ���������
// ��
// ˵����
// ���ûص�����
// ����ֵ��
// ��
// ������
// 2010-06-30 ���
//////////////////////////////////////////////////////////////////////
void CMyTimer::SetCallback(ITimerCallBack *pCallback)
{
	m_pTimerCallback = pCallback;
}

//////////////////////////////////////////////////////////////////////
// SetTimer(Int32 iInterval)
// ���������
// iInterval	���õ�ʱ�䣬�Ժ���Ϊ��λ
// ���������
// ��
// ˵����
// ���ü�ʱ��
// ����ֵ��
// ��
// ������
// 2010-06-30 ���
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
// ���������
// iInterval	���õ�ʱ�䣬�Ժ���Ϊ��λ
// ���������
// ��
// ˵����
// ���ü�ʱ��
// ����ֵ��
// ��
// ������
// 2010-06-30 ���
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
// ���������
// ��
// ���������
// ��
// ˵����
// ȡ����ʱ��
// ����ֵ��
// ��
// ������
// 2010-06-30 ���
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
// ���������
// iInterval	���õ�ʱ�䣬��СʱΪ��λ
// ���������
// ��
// ˵����
// ���ü�ʱ��
// ����ֵ��
// ��
// ������
// 2010-06-30 ���
//////////////////////////////////////////////////////////////////////
void CMyTimer::SetTimerInHour(Int32 iInterval)
{
	SetTimer(iInterval * 60 * 60 * 1000);
}

//////////////////////////////////////////////////////////////////////
// SetTimerInMinute(Int32 iInterval)
// ���������
// iInterval	���õ�ʱ�䣬�Է�Ϊ��λ
// ���������
// ��
// ˵����
// ���ü�ʱ��
// ����ֵ��
// ��
// ������
// 2010-06-30 ���
//////////////////////////////////////////////////////////////////////
void CMyTimer::SetTimerInMinute(Int32 iInterval)
{
	SetTimer(iInterval * 60 * 1000);
}

//////////////////////////////////////////////////////////////////////
// SetTimerInSecond(Int32 iInterval)
// ���������
// iInterval	���õ�ʱ�䣬����Ϊ��λ
// ���������
// ��
// ˵����
// ���ü�ʱ��
// ����ֵ��
// ��
// ������
// 2010-06-30 ���
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
// ���������
// dwMilliseconds	���õ�ʱ�䣬�Ժ���Ϊ��λ
// ���������
// ��
// ˵����
// ���õȴ���ʵ��Sleep����
// ����ֵ��
// ��
// ������
// 2010-09-07 ���
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
