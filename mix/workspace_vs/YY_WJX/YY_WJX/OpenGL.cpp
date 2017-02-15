// OpenGL.cpp: implementation of the OpenGL class.
//程序设计：唐明理	2005.2
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

BOOL OpenGL::SetupPixelFormat(HDC hDC0)//检测安装OpenGL
{	
	int nPixelFormat;					  // 象素点格式
	hDC=hDC0;
	PIXELFORMATDESCRIPTOR pfd = { 
		sizeof(PIXELFORMATDESCRIPTOR),    // pfd结构的大小 
		1,                                // 版本号 
		PFD_DRAW_TO_WINDOW |              // 支持在窗口中绘图 
		PFD_SUPPORT_OPENGL |              // 支持 OpenGL 
		PFD_DOUBLEBUFFER,                 // 双缓存模式 
		PFD_TYPE_RGBA,                    // RGBA 颜色模式 
		16,                               // 24 位颜色深度 
		0, 0, 0, 0, 0, 0,                 // 忽略颜色位 
		0,                                // 没有非透明度缓存 
		0,                                // 忽略移位位 
		0,                                // 无累加缓存 
		0, 0, 0, 0,                       // 忽略累加位 
		16,                               // 32 位深度缓存     
		0,                                // 无模板缓存 
		0,                                // 无辅助缓存 
		PFD_MAIN_PLANE,                   // 主层 
		0,                                // 保留 
		0, 0, 0                           // 忽略层,可见性和损毁掩模 
	}; 
	if (!(nPixelFormat = ChoosePixelFormat(hDC, &pfd)))
	{ MessageBox(NULL,"没找到合适的显示模式","Error",MB_OK|MB_ICONEXCLAMATION);
	return FALSE;
	}
	SetPixelFormat(hDC,nPixelFormat,&pfd);//设置当前设备的像素点格式
	hRC = wglCreateContext(hDC);          //获取渲染描述句柄
	wglMakeCurrent(hDC, hRC);             //激活渲染描述句柄

	return TRUE;
}
void OpenGL::init(int Width, int Height)
{	
	glViewport(0,0,Width,Height);			// 设置OpenGL视口大小。	
	glMatrixMode(GL_PROJECTION);			// 设置当前矩阵为投影矩阵。
	glLoadIdentity();						// 重置当前指定的矩阵为单位矩阵
	gluPerspective							// 设置透视图
		( 54.0f,							// 透视角设置为 45 度
		(GLfloat)Width/(GLfloat)Height,	// 窗口的宽与高比
		0.1f,								// 视野透视深度:近点1.0f
		3000.0f							// 视野透视深度:始点0.1f远点1000.0f
		);
	// 这和照象机很类似，第一个参数设置镜头广角度，第二个参数是长宽比，后面是远近剪切。
	glMatrixMode(GL_MODELVIEW);				// 设置当前矩阵为模型视图矩阵
	glLoadIdentity();						// 重置当前指定的矩阵为单位矩阵
	//====================================================
}
void OpenGL::Render()//OpenGL图形处理
{	
	glClearColor(0.0f, 0.0f, 0.6f, 1.0f);			 // 设置刷新背景色
	glClear(GL_COLOR_BUFFER_BIT|GL_DEPTH_BUFFER_BIT);// 刷新背景
	glLoadIdentity();								 // 重置当前的模型观察矩阵
	DisplayScene();
	play();
	glFlush();										 // 更新窗口
	SwapBuffers(hDC);								 // 切换缓冲区
	r+=1;if(r>360) r=0;
}
void OpenGL::CleanUp()
{	
	wglMakeCurrent(hDC, NULL);                       //清除OpenGL

	wglDeleteContext(hRC);                           //清除OpenGL
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
