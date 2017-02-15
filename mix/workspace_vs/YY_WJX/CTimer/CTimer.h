/*
 * CTimer.h
 *
 *  Created on: 2011-11-24
 *      Author: Administrator
 */

#ifndef CTIMER_H_
#define CTIMER_H_

#include "LRTimer.h"
#include "..\Common\common.h"
#include "..\transaction\inc\ITimer.h"
#include "..\transaction\inc\ITimerCallBack.h"

namespace TJU_CTIMER
{

class CTimer
{
public:
	CTimer(ETIMERTYPE eTimerType = InviteCT_A);
	~CTimer();
	virtual Int32 Schedule(Int32 imsInterval, ITimerCallBack *pCallBack);
	void SetCallback(ITimerCallBack *pCallback);
	void SetTimerInHour(Int32 iInterval);
	void SetTimerInMinute(Int32 iInterval);
	void SetTimerInSecond(Int32 iInterval);
	void SetTimerInMsec(Int32 iInterval);
	Bool CancelTimer();
	static void Sleep(UInt64 dwMilliseconds);

	static void Callback(VOID*);

private:
	void SetTimer(Int32 iInterval);

	ITimerCallBack *m_pTimerCallback;
	ETIMERTYPE m_eTimerType;
    bool m_bSingleShot;
	LRTimer *m_pTimer;
};

}

#endif /* CTIMER_H_ */
