#include "CTimer.h"

CCTimer::CCTimer(void)
{
	m_pTimer = new CMyTimer();
	m_pTimer->Schedule(3000,this);
	delete m_pTimer;

	m_pTimer = new CMyTimer();
	m_pTimer->Schedule(10000,this);
	delete m_pTimer;

	m_pTimer = new CMyTimer();
	m_pTimer->Schedule(30000,this);
	delete m_pTimer;
}

CCTimer::~CCTimer(void)
{

}

void CCTimer::HandleTimeOut(ETIMERTYPE iTimerType)
{
	int jj = 0;
}
