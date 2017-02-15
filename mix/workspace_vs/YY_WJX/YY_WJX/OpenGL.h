// OpenGL.h: interface for the OpenGL class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_OPENGL_H__17B7289C_7956_41C5_89B9_621E3C435389__INCLUDED_)
#define AFX_OPENGL_H__17B7289C_7956_41C5_89B9_621E3C435389__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "bsipic.h"
#include "YY_BaseBall.h"

class OpenGL  
{	
public:
	OpenGL();
	virtual ~OpenGL();

	void DisplayScene();
public:
	bsipic  m_bsipic;	// ����bsipic�����
	YY_BaseBall * m_pBall;
	HDC		hDC;		// GDI�豸������
	HGLRC	hRC;		// ������ɫ������
	BOOL	SetupPixelFormat(HDC hDC);
	void	init(int Width, int Height);
	void	Render();
	void	CleanUp();
	void	play();

private:GLdouble	g_eye[3];		//
		GLdouble	g_look[3];		//
		float		rad_xy;	
		float       rad_z;
		float		g_Angle;
		float       g_AngleUP;
};

#endif // !defined(AFX_OPENGL_H__17B7289C_7956_41C5_89B9_621E3C435389__INCLUDED_)
