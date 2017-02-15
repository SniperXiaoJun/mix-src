#pragma once

#include "..\transaction\ITimerCallBack.h"
#include "../Timer/Timer.h"


class CCTimer: public ITimerCallBack
{
public:
	CCTimer(void);
	~CCTimer(void);

    void HandleTimeOut(ETIMERTYPE iTimerType);

	CMyTimer * m_pTimer;
};
