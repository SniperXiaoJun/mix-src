// WIN32MFC_UDP.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// CWIN32MFC_UDPApp:
// �йش����ʵ�֣������ WIN32MFC_UDP.cpp
//

class CWIN32MFC_UDPApp : public CWinApp
{
public:
	CWIN32MFC_UDPApp();

// ��д
	public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern CWIN32MFC_UDPApp theApp;