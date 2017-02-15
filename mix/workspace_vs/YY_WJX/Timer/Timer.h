#ifndef _TIMER_H_
#define _TIMER_H_
#ifdef TIMER_EXPORTS
#define TIMER_API __declspec(dllexport)
#else
#define TIMER_API __declspec(dllimport)
#endif

#include <windows.h>

#include "..\Common\common.h"
#include "..\transaction\ITimer.h"
#include "..\transaction\ITimerCallBack.h"


class TIMER_API CMyTimer:public ITimer
{
public:
	CMyTimer(ETIMERTYPE eTimerType = InviteCT_A);
	~CMyTimer();
	
	virtual Int32 Schedule(Int32 imsInterval, ITimerCallBack *pCallBack);
	void SetCallback(ITimerCallBack *pCallback);
	void SetTimerInHour(Int32 iInterval);
	void SetTimerInMinute(Int32 iInterval);
	void SetTimerInSecond(Int32 iInterval);
	void SetTimerInMsec(Int32 iInterval);
	Bool CancelTimer();
	static void Sleep(UInt64 dwMilliseconds);

	static void Callback(CMyTimer * pTimer);

private:
	void SetTimer(Int32 iInterval);

	int  m_iAccuracy;
	int  m_iMsSecond;
	int  m_iTimerID;
	bool m_bActive;
	bool m_bSingleShot;
	ITimerCallBack * m_pTimerCallback;
	ETIMERTYPE m_eTimerType;
};

#endif // TIMER_H