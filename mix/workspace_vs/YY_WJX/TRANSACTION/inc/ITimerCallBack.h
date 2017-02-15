//-------------------------------------------------------------------------------------
// 
// �ļ���: ITimerCallBack.h
// 
// ������: Yan haicheng 
// 
// ��  ��: 2010-08-03
//
// ��  ��: ͷ�ļ������嶨ʱ�����ڻص���
//
// ��  ��: 1.0
// 
//-------------------------------------------------------------------------------------

#ifndef _ITIMERCALLBACK_H__
#define _ITIMERCALLBACK_H__

enum ETIMERTYPE
{
	InviteCT_A		= 0,	
	InviteCT_B		= 1,
	InviteCT_D		= 2,
	InviteST_G		= 3,
	InviteST_H		= 4,
	InviteST_I		= 5,
	NONInviteCT_E	= 6,
	NONInviteCT_F	= 7,
	NONInviteCT_K	= 8,
	NONInviteST_J	= 9
};

class ITimerCallBack
{
public:
	virtual void HandleTimeOut(ETIMERTYPE iTimerType) = 0;
};

#endif