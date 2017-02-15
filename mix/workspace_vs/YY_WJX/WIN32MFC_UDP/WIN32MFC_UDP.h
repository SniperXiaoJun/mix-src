// WIN32MFC_UDP.h : PROJECT_NAME 应用程序的主头文件
//

#pragma once

#ifndef __AFXWIN_H__
	#error "在包含此文件之前包含“stdafx.h”以生成 PCH 文件"
#endif

#include "resource.h"		// 主符号


// CWIN32MFC_UDPApp:
// 有关此类的实现，请参阅 WIN32MFC_UDP.cpp
//

class CWIN32MFC_UDPApp : public CWinApp
{
public:
	CWIN32MFC_UDPApp();

// 重写
	public:
	virtual BOOL InitInstance();

// 实现

	DECLARE_MESSAGE_MAP()
};

extern CWIN32MFC_UDPApp theApp;