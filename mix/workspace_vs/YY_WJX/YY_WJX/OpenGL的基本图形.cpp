// OpenGL的基本图形.cpp : Defines the entry point for the application.
//程序设计：唐明理	2005.2
//E_mail cqtml@163.com
#include "stdafx.h"
#include "OpenGL.h"
//////////////////////////////////////////////////////////
OpenGL* m_OpenGL;
HDC		hDC;		// GDI设备句柄,将窗口连接到 GDI( 图形设备接口)
HGLRC	hRC=NULL;	// 渲染描述句柄,将OpenGL调用连接到设备描述表 
HWND	hWnd=NULL;	// 保存 Windows 分配给程序的窗口句柄
int		Width = 800;// 窗口宽
int		Height= 600;// 窗口高
int		bits  = 16;	// 颜色深度
////////////////////////////////////////////////
void GameLoop()
{   MSG msg; 
    BOOL fMessage;
    PeekMessage(&msg, NULL, 0U, 0U, PM_NOREMOVE);
    while(msg.message != WM_QUIT)	// 消息循环
    {   fMessage = PeekMessage(&msg, NULL, 0U, 0U, PM_REMOVE);
        if(fMessage)				//有消息
			{ TranslateMessage(&msg);
              DispatchMessage(&msg);
			}
        else  m_OpenGL->Render();	//无消息
    }
}
LRESULT WINAPI MsgProc(HWND hWnd,UINT message,WPARAM wParam,LPARAM lParam )// 消息处理
{	switch(message)
	{	case WM_CREATE:						// 建立窗口
			hDC = GetDC(hWnd);				// 获取当前窗口的设备句柄
			m_OpenGL->SetupPixelFormat(hDC);// 调用显示模式安装功能
			return 0;		break;
		case WM_CLOSE:						// 关闭窗口
			m_OpenGL->CleanUp();			// 结束处理
			PostQuitMessage(0);
			return 0;		break;
		case WM_SIZE:						// 窗口尺寸变化
			Height = HIWORD(lParam);		// 窗口的高
			Width  = LOWORD(lParam);		// 窗口的宽
			if (Height==0)	Height=1;		// 防止被0 除
			m_OpenGL->init(Width,Height);
			return 0;		break;
		case WM_DESTROY:					// 退出消息
            PostQuitMessage(0);
            return 0;		break;
        case WM_KEYUP:						// 按ESC退出，全屏模式必需要加入的退出方式。
            switch (wParam)
            { case VK_ESCAPE:
					m_OpenGL->CleanUp();	// 结束处理
				    PostQuitMessage(0);
				    return 0;break;
            } 
		default:			break;
	}
	return (DefWindowProc(hWnd, message, wParam, lParam));
}
INT WINAPI WinMain(HINSTANCE hInst,HINSTANCE,LPSTR,INT )// WinMain程序入口
{   // 注册窗口类
	bool fullScreen =TRUE;
	DWORD	dwExStyle;		// Window 扩展风格
	DWORD	dwStyle;		// Window 窗口风格
	RECT	windowRect;		// 窗口尺寸
	int		nX=0,nY=0;
	
	if (MessageBox(NULL,"使用全屏模式吗?", "将进入OpenGL,选择显示模式",
		           MB_YESNO|MB_ICONQUESTION|MB_SYSTEMMODAL)==IDNO)
		{fullScreen =false;}			// 选择窗口模式
	if (fullScreen)						// 选择全屏模式
	{	DEVMODE dmScr;					// 设备模式
		memset(&dmScr,0,sizeof(dmScr));	// 确保内存分配
		dmScr.dmSize=sizeof(dmScr);		// Devmode 结构的大小
		dmScr.dmPelsWidth = Width;		// 屏幕宽
		dmScr.dmPelsHeight= Height;		// 屏幕高
		dmScr.dmBitsPerPel= 16;			// 色彩深度
		dmScr.dmDisplayFrequency=75;	// 刷屏速度
		dmScr.dmFields=DM_BITSPERPEL|DM_PELSWIDTH|DM_PELSHEIGHT|DM_DISPLAYFREQUENCY;
		if (ChangeDisplaySettings(&dmScr, CDS_FULLSCREEN) != DISP_CHANGE_SUCCESSFUL)
			{fullScreen=FALSE;}
		dwExStyle=WS_EX_APPWINDOW;		// Window 扩展风格
		dwStyle=WS_POPUP;				// Window 窗口风格
		ShowCursor(FALSE);				// 隐藏鼠标
	}
	else
	{	dwExStyle=WS_EX_APPWINDOW|WS_EX_WINDOWEDGE;	// 使窗口具有3D外观
		dwStyle=WS_OVERLAPPEDWINDOW;				// 使用标准窗口
		//WS_OVERLAPPEDWINDOW是有标题栏,窗口菜单,最大、小化按钮和可调整尺寸的窗口
		int wid=GetSystemMetrics(SM_CXSCREEN);		// 获取当前屏幕宽
		int hei=GetSystemMetrics(SM_CYSCREEN);		// 获取当前屏幕高
		nX=(wid-Width)/2;nY=(hei-Height)/2;			// 计算窗口居中用
	}
//-------------------------------------------------------------------
	AdjustWindowRectEx(&windowRect,dwStyle,FALSE,dwExStyle);
									//根据窗口风格来调整窗口尺寸达到要求的大小
	char cc[]="tml";
    WNDCLASSEX wc = { sizeof(WNDCLASSEX), CS_CLASSDC, MsgProc, 0L, 0L, 
                      GetModuleHandle(NULL), NULL, NULL, NULL, NULL,
                      cc, NULL };
    RegisterClassEx( &wc );
	m_OpenGL=new OpenGL();//
	hWnd = CreateWindowEx(NULL,cc,"学OpenGL编3D游戏 [ 2.OpenGL的基本图形 ])",
						  dwStyle|WS_CLIPCHILDREN|WS_CLIPSIBLINGS,
						  nX, nY,Width, Height,
						  NULL,NULL,hInst,NULL);	// 创建窗口
	ShowWindow( hWnd, SW_SHOWDEFAULT );				// 显示窗口
	UpdateWindow( hWnd );							// 刷新窗口
	GameLoop();										// 进入消息循环
    return 0;
}