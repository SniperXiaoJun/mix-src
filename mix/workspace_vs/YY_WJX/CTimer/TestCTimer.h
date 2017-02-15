
#include "CTimer.h"
#include "..\transaction\inc\ITimerCallBack.h"

class TestCTimer: public ITimerCallBack
{
public:
	TestCTimer(void);
	~TestCTimer(void);

	void HandleTimeOut(ETIMERTYPE iTimerType);

private:
	TJU_CTIMER::CTimer * m_pTimer;
};
