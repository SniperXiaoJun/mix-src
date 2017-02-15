#include "TestCTimer.h"

TestCTimer::TestCTimer(void)
{
	//m_pTimer->SetCallback(this);

	m_pTimer = new TJU_CTIMER::CTimer();
	m_pTimer->Schedule(3000,this);
}

TestCTimer::~TestCTimer(void)
{
}


void TestCTimer::HandleTimeOut(ETIMERTYPE iTimerType)
{
	int a = 0;

	int b = 0;
}
