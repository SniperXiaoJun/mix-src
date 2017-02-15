// stdafx.h : include file for standard system include files,
//  or project specific include files that are used frequently, but
//      are changed infrequently
//

#if !defined(AFX_STDAFX_H__A9DB83DB_A9FD_11D0_BFD1_444553540000__INCLUDED_)
#define AFX_STDAFX_H__A9DB83DB_A9FD_11D0_BFD1_444553540000__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#define WIN32_LEAN_AND_MEAN		// Exclude rarely-used stuff from Windows headers

#include <windows.h>	// Windows的头文件

#include <mmsystem.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <assert.h>
#include <gl\gl.h>		// OpenGL32库的头文件
#include <gl\glu.h>		// GLu32库的头文件
#include <gl\glaux.h>	// GLaux库的头文件
#pragma comment( lib, "winmm.lib")
#pragma comment( lib, "opengl32.lib")	// OpenGL32连接库
#pragma comment( lib, "glu32.lib")		// GLu32连接库
#pragma comment( lib, "glaux.lib")		// GLaux连接库
// TODO: reference additional headers your program requires here

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_STDAFX_H__A9DB83DB_A9FD_11D0_BFD1_444553540000__INCLUDED_)
