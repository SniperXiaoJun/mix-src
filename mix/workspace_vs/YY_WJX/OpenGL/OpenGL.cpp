// OpenGL.cpp: implementation of the OpenGL class.
//������ƣ�������	2005.2
//E_mail cqtml@163.com
//////////////////////////////////////////////////////////////////////
#include "stdafx.h"
#include "OpenGL.h"
//////////////////////////////////////////////////////////////////////
#include "stdafx.h"
#include "OpenGL.h"
//////////////////////////////////////////////////////////////////////
extern HWND	hWnd;

//////////////////////////////////////////////////////////////////////
OpenGL::OpenGL()
{
}
OpenGL::~OpenGL()
{	CleanUp();
}
BOOL OpenGL::SetupPixelFormat(HDC hDC0)//��ⰲװOpenGL
{	int nPixelFormat;					  // ���ص��ʽ
	hDC=hDC0;
	PIXELFORMATDESCRIPTOR pfd = { 
	    sizeof(PIXELFORMATDESCRIPTOR),    // pfd�ṹ�Ĵ�С 
	    1,                                // �汾�� 
	    PFD_DRAW_TO_WINDOW |              // ֧���ڴ����л�ͼ 
	    PFD_SUPPORT_OPENGL |              // ֧�� OpenGL 
	    PFD_DOUBLEBUFFER,                 // ˫����ģʽ 
	    PFD_TYPE_RGBA,                    // RGBA ��ɫģʽ 
	    16,                               // 24 λ��ɫ��� 
	    0, 0, 0, 0, 0, 0,                 // ������ɫλ 
	    0,                                // û�з�͸���Ȼ��� 
	    0,                                // ������λλ 
	    0,                                // ���ۼӻ��� 
	    0, 0, 0, 0,                       // �����ۼ�λ 
	    16,                               // 32 λ��Ȼ���     
	    0,                                // ��ģ�建�� 
	    0,                                // �޸������� 
	    PFD_MAIN_PLANE,                   // ���� 
	    0,                                // ���� 
	    0, 0, 0                           // ���Բ�,�ɼ��Ժ������ģ 
	}; 
	if (!(nPixelFormat = ChoosePixelFormat(hDC, &pfd)))
		{ MessageBox(NULL,"û�ҵ����ʵ���ʾģʽ","Error",MB_OK|MB_ICONEXCLAMATION);
	      return FALSE;
		}
	SetPixelFormat(hDC,nPixelFormat,&pfd);//���õ�ǰ�豸�����ص��ʽ
	hRC = wglCreateContext(hDC);          //��ȡ��Ⱦ�������
	wglMakeCurrent(hDC, hRC);             //������Ⱦ�������
	return TRUE;
}
void OpenGL::init(int Width, int Height)
{	glViewport(0,0,Width,Height);			// ����OpenGL�ӿڴ�С��	
	glMatrixMode(GL_PROJECTION);			// ���õ�ǰ����ΪͶӰ����
	glLoadIdentity();						// ���õ�ǰָ���ľ���Ϊ��λ����
	gluPerspective							// ����͸��ͼ
		( 54.0f,							// ͸�ӽ�����Ϊ 45 ��
		  (GLfloat)Width/(GLfloat)Height,	// ���ڵĿ���߱�
		  0.1f,								// ��Ұ͸�����:����1.0f
		  3000.0f							// ��Ұ͸�����:ʼ��0.1fԶ��1000.0f
		);
	// �������������ƣ���һ���������þ�ͷ��Ƕȣ��ڶ��������ǳ���ȣ�������Զ�����С�
	glMatrixMode(GL_MODELVIEW);				// ���õ�ǰ����Ϊģ����ͼ����
	glLoadIdentity();						// ���õ�ǰָ���ľ���Ϊ��λ����
//====================================================
}
void OpenGL::Render()//OpenGLͼ�δ���
{	
	glClearColor(0.0f, 0.0f, 0.3f, 1.0f);			 // ����ˢ�±���ɫ
	glClear(GL_COLOR_BUFFER_BIT|GL_DEPTH_BUFFER_BIT);// ˢ�±���
	glLoadIdentity();								 // ���õ�ǰ��ģ�͹۲����

	static float r = 1;
	r++;

	glPushMatrix(); 
	glTranslatef ( 0, -4,-13);glRotatef(r,1.0,1.0,1.0);
	glColor3f(0.7f, 0.7f, 0.7f);auxSolidCone(1,10);
	glPopMatrix();
	glPushMatrix(); 
	glTranslatef ( 5,-4,-13);glRotatef(r,1.0,1.0,1.0); 
	glColor3f(0.4f, 0.4f, 0.4f);auxWireTeapot(1);
	glPopMatrix();

	glFlush();										 // ���´���
	SwapBuffers(hDC);								 // �л�������
}
void OpenGL::CleanUp()//���OpenGL
{
	 wglMakeCurrent(hDC, NULL);                       //���OpenGL
	 wglDeleteContext(hRC);                           //���OpenGL

}
