//-------------------------------------------------------------------------------------
// 
// 文件名: ITimerCallBack.h
// 
// 创建人: Yan haicheng 
// 
// 日  期: 2010-08-03
//
// 描  述: 头文件，定义定时器到期回调类
//
// 版  本: 1.0
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