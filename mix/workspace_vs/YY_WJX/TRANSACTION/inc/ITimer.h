//-------------------------------------------------------------------------------------
// 
// �ļ���: ITimer.h
// 
// ������: Yan haicheng 
// 
// ��  ��: 2010-08-03
//
// ��  ��: ͷ�ļ������嶨ʱ����
//
// ��  ��: 1.0
// 
//-------------------------------------------------------------------------------------

#ifndef _ITIMER_H__
#define _ITIMER_H__

#include "ITimerCallBack.h"

class ITimer
{
public:
	virtual ~ITimer(){};
	//��ʱ����λΪ����
	virtual int Schedule(int imsInterval, ITimerCallBack *pCallBack) = 0;
};

#endif
