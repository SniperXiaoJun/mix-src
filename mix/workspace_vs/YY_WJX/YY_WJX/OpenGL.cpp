// OpenGL.cpp: implementation of the OpenGL class.
//������ƣ�������	2005.2
//E_mail cqtml@163.com
//////////////////////////////////////////////////////////////////////
#include "stdafx.h"
#include "OpenGL.h"

extern HWND	hWnd;
float	r;
//////////////////////////////////////////////////////////////////////
OpenGL::OpenGL()
{
	m_pBall = new YY_BaseBall(5, 5, 5, 5);

	g_eye[0]= 0;//
	g_eye[1]= 0;//
	g_eye[2]= 0;//
	g_Angle=0;
	g_AngleUP = 0;
}

OpenGL::~OpenGL()
{
	CleanUp();
	delete m_pBall;
	m_pBall = NULL;
}

BOOL OpenGL::SetupPixelFormat(HDC hDC0)//��ⰲװOpenGL
{	
	int nPixelFormat;					  // ���ص��ʽ
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
{	
	glViewport(0,0,Width,Height);			// ����OpenGL�ӿڴ�С��	
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
	glClearColor(0.0f, 0.0f, 0.6f, 1.0f);			 // ����ˢ�±���ɫ
	glClear(GL_COLOR_BUFFER_BIT|GL_DEPTH_BUFFER_BIT);// ˢ�±���
	glLoadIdentity();								 // ���õ�ǰ��ģ�͹۲����
	DisplayScene();
	play();
	glFlush();										 // ���´���
	SwapBuffers(hDC);								 // �л�������
	r+=1;if(r>360) r=0;
}
void OpenGL::CleanUp()
{	
	wglMakeCurrent(hDC, NULL);                       //���OpenGL

	wglDeleteContext(hRC);                           //���OpenGL
}
void OpenGL::play()
{
	Sleep(10);

	glPushMatrix();

	glTranslatef( 10,10,5);

	glColor3f(1.0f, 1.0f, 1.0f);
	m_bsipic.Esquare();

	glPopMatrix();

	glPushMatrix();

	glTranslatef( 5,10,5);

	glColor3f(1.0f, 1.0f, 1.0f);
	m_bsipic.Esquare();

	glPopMatrix();

	glPushMatrix();

	glTranslatef( 10,5,5);

	glColor3f(1.0f, 1.0f, 1.0f);
	m_bsipic.Esquare();

	glPopMatrix();

	glPushMatrix();

	glTranslatef( 10,10,-5);

	glColor3f(1.0f, 1.0f, 1.0f);
	m_bsipic.Esquare();

	glPopMatrix();

	glPushMatrix();

	glTranslatef( 5,10,-5);

	glColor3f(1.0f, 1.0f, 1.0f);
	m_bsipic.Esquare();

	glPopMatrix();

	glPushMatrix();

	glTranslatef( 10,5,-5);

	glColor3f(1.0f, 1.0f, 1.0f);
	m_bsipic.Esquare();

	glPopMatrix();


	glPushMatrix();
	glTranslatef( 0,0,-30);
	glRotatef(100, 1.0, 0.0, 0.0);

	glPushMatrix(); 
	glRotatef(-r, 0.0, 0.0, 1.0);

	glPushMatrix(); 
	glTranslatef( 10,0,0);
	//glRotatef(-r,0.0,0.0,0.0);
	glColor3f(1.f, 0.0f, 0.0f);
	auxSolidSphere(1);
	glPopMatrix();

	glPushMatrix(); 
	glTranslatef( 0,0,0);
	//glRotatef(-r,0.0,0.0,0.0); 
	glColor3f(0.0f, 1.0f, 0.0f);
	auxSolidSphere(2);
	glPopMatrix();

	glPopMatrix();

	glPopMatrix();

	glPushMatrix(); 
	glRotatef(r,0,0,1);
	glPushMatrix(); 
	glPointSize(4);	
	glTranslatef (-5, 4,-13);glRotatef(r,1.0,1.0,1.0);
	glColor3f(1.0f, 0.0f, 0.0f);m_bsipic.Point();	
	glPopMatrix();
	glPushMatrix(); 
	glTranslatef ( 0, 4,-13);glRotatef(r,1.0,1.0,1.0);
	glColor3f(0.0f, 1.0f, 0.0f);m_bsipic.Line();	
	glPopMatrix();
	glPushMatrix();
	glTranslatef ( 5, 4,-13);glRotatef(r,1.0,1.0,1.0); 
	glColor3f(0.0f, 0.0f, 1.0f);m_bsipic.Triangle();
	glPopMatrix();
	glPushMatrix();
	glTranslatef (-5, 0,-13);glRotatef(r,1.0,1.0,1.0); 
	glColor3f(1.0f, 1.0f, 0.0f);m_bsipic.Square();
	glPopMatrix();
	glPushMatrix();
	glTranslatef ( 0, 0,-13);glRotatef(r,1.0,1.0,1.0);
	glColor3f(0.0f, 1.0f, 1.0f);m_bsipic.Esquare();	
	glPopMatrix();
	glPushMatrix(); 
	glTranslatef ( 5, 0,-13);glRotatef(r,1.0,1.0,1.0); 
	glColor3f(1.0f, 0.0f, 1.0f);m_bsipic.Park();
	glPopMatrix();
	glPushMatrix(); 
	glTranslatef (-5,-4,-13);glRotatef(r,1.0,1.0,1.0); 
	glColor3f(1.0f, 1.0f, 1.0f);m_bsipic.Pillar();	
	glPopMatrix();
	glPushMatrix(); 
	glTranslatef ( 0, -4,-13);glRotatef(r,1.0,1.0,1.0);
	glColor3f(0.7f, 0.7f, 0.7f);auxSolidCone(1,1);
	glPopMatrix();
	glPushMatrix(); 
	glTranslatef ( 5,-4,-13);glRotatef(r,1.0,1.0,1.0); 
	glColor3f(0.4f, 0.4f, 0.4f);auxWireSphere(1);
	glPopMatrix();
	glPopMatrix();
}

void OpenGL::DisplayScene()
{ 
	float speed = 0.2f;	

	if (KEY_DOWN(VK_SHIFT))  speed =speed*4;
	if (KEY_DOWN(VK_LEFT))   g_Angle-=speed*2;
	if (KEY_DOWN(VK_RIGHT))  g_Angle+=speed*2;
	rad_xy = float (3.13149* g_Angle/180.0f);
	
	if (KEY_DOWN(33)) g_AngleUP -= speed * 2;
	if (KEY_DOWN(34)) g_AngleUP += speed * 2;
	if (g_AngleUP < -90)	g_AngleUP  = -90;
	if (g_AngleUP > 90)	g_AngleUP  = 90;

	rad_z = float(3.13149 * g_AngleUP/180.0f);

	if (KEY_DOWN(VK_UP))  
	{ 
		g_eye[0]+=sin(rad_xy)*speed * cos(rad_z);
		g_eye[1]+=cos(rad_xy)*speed * cos(rad_z);
		g_eye[2]+=sin(rad_z);
	}
	if (KEY_DOWN(VK_DOWN))
	{
		g_eye[0]-=sin(rad_xy)*speed * cos(rad_z);
		g_eye[1]-=cos(rad_xy)*speed * cos(rad_z);
		g_eye[2]-=sin(rad_z);
	}

	g_look[0] = float(g_eye[0] + sin(rad_xy)*speed * cos(rad_z));
	g_look[1] = float(g_eye[1] + cos(rad_xy)*speed * cos(rad_z));
	g_look[2] = float(g_eye[2] + sin(rad_z));

	gluLookAt(g_eye[0],g_eye[1],g_eye[2],g_look[0],g_look[1],g_look[2], g_eye[0],g_eye[1],g_eye[2]+1.0);

	glBegin(GL_POINTS);//
	glVertex3f( g_eye[0], g_eye[1],g_eye[2]);
	glVertex3f( g_look[0], g_look[1],g_look[2]);
	glEnd();
}
