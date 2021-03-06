#include <windows.h>
#include <gl/gl.h>
#include <gl/glut.h>

static GLfloat xRot = 0.0f;
static GLfloat yRot = 0.0f;
BOOL bDepth = FALSE;//􂏅􁑺􂌟􄆩􁓔􀝇
BOOL bCull = FALSE;//􀠨􄰸􁓔􀝇

void SetupRC(void)
{

	glClearColor(0.0f, 0.0f, 0.0f, 1.0f );

	glShadeModel(GL_FLAT);
}
void ChangeSize(int w, int h)
{
	if(h == 0) h = 1;
	glViewport(0, 0, w, h);
	glMatrixMode(GL_PROJECTION);
	glLoadIdentity();
	if (w <= h)
		glOrtho (-100.0f, 100.0f, -100.0f*h/w, 100.0f*h/w, -100.0f, 100.0f);
	else
		glOrtho (-100.0f*w/h, 100.0f*w/h, -100.0f, 100.0f, -100.0f, 100.0f);
	glMatrixMode(GL_MODELVIEW);
	glLoadIdentity();
}

void RenderScene(void)
{

	glClear(GL_COLOR_BUFFER_BIT| GL_DEPTH_BUFFER_BIT);

	if(bDepth)
		glEnable(GL_DEPTH_TEST);
	else
		glDisable(GL_DEPTH_TEST);

	if(bCull)
		glEnable(GL_CULL_FACE);
	else
		glDisable(GL_CULL_FACE);


	glPushMatrix();
	glRotatef(xRot, 1.0f, 0.0f, 0.0f);
	glRotatef(yRot, 0.0f, 1.0f, 0.0f);

	glFrontFace(GL_CW);

	glBegin(GL_TRIANGLE_FAN);
	glVertex3f(0.0, 0.0, 80.0);
	glVertex3f(0.0, 50.0, 0.0);
	glColor3f(1.0,0.0,0.0);
	glVertex3f(50.0, -50.0, 0.0);
	glColor3f(0.0,1.0,0.0);
	glVertex3f(-50.0, -50.0, 0.0);
	glColor3f(0.0,0.0,1.0);
	glVertex3f(0.0, 50.0, 0.0);
	glEnd();

	glBegin(GL_TRIANGLE_FAN);
	glVertex3f(0.0, 50.0, 0.0);
	glVertex3f(50.0, -50.0, 0.0);
	glColor3f(1.0,1.0,0.0);
	glVertex3f(-50.0, -50.0, 0.0);
	glEnd();
	glPopMatrix();

	glutSwapBuffers();
}
void SpecialKeys(int key, int x, int y)
{
	if(key == GLUT_KEY_UP) xRot-= 5.0f;
	if(key == GLUT_KEY_DOWN) xRot += 5.0f;
	if(key == GLUT_KEY_LEFT) yRot -= 5.0f;
	if(key == GLUT_KEY_RIGHT) yRot += 5.0f;
	if(xRot > 356.0f) xRot = 0.0f;
	if(xRot < -1.0f) xRot = 355.0f;
	if(yRot > 356.0f) yRot = 0.0f;
		if(yRot < -1.0f) yRot = 355.0f;

	glutPostRedisplay();
}
void ProcessMenu(int value)
{
	switch(value)
	{
	case 1:
		bDepth = !bDepth;
		break;
	case 2:
		bCull = !bCull;
		break;
	default:
		break;
	}
	glutPostRedisplay();
}
int main(int argc, char* argv[])
{
	glutInit(&argc, argv);
	glutInitDisplayMode(GLUT_DOUBLE | GLUT_RGB );
	glutCreateWindow("三棱锥");
	glutReshapeFunc(ChangeSize);
	glutSpecialFunc(SpecialKeys);
	glutDisplayFunc(RenderScene);

	glutCreateMenu(ProcessMenu);
	glutAddMenuEntry("深度测试",1);
	glutAddMenuEntry("剔除表面",2);
	glutAttachMenu(GLUT_RIGHT_BUTTON);
	SetupRC();
	glutMainLoop();
	return 0;
}










//////////Triangle.c
////////#include <windows.h>
////////#include <gl/gl.h>
////////#include <gl/glut.h>
////////
////////static GLfloat xRot = 0.0f;
////////static GLfloat yRot = 0.0f;
////////
////////BOOL bWinding = TRUE;
////////
////////void SetupRC(void)
////////{
////////
////////	glClearColor(0.0f, 0.0f, 0.0f, 1.0f );
////////}
////////void ChangeSize(int w, int h)
////////{
////////	if(h == 0) h = 1;
////////	glViewport(0, 0, w, h);
////////	glMatrixMode(GL_PROJECTION);
////////	glLoadIdentity();
////////	if (w <= h)
////////		glOrtho(-100.0f,100.0f,-100.0f*h/w,100.0f*h/w,-100.0f,100.0f);
////////	else
////////		glOrtho(-100.0f*w/h,100.0f*w/h,-100.0f,100.0f,-100.0f,100.0f);
////////	glMatrixMode(GL_MODELVIEW);
////////	glLoadIdentity();
////////}
////////
////////void RenderScene(void)
////////{
////////	glClear(GL_COLOR_BUFFER_BIT);
////////
////////	glPushMatrix();
////////	glRotatef(xRot, 1.0f, 0.0f, 0.0f);
////////	glRotatef(yRot, 0.0f, 1.0f, 0.0f);
////////
////////	glPointSize(5);
////////	glLineWidth(5);
////////
////////	if (bWinding)
////////		glFrontFace(GL_CW);
////////	else
////////		glFrontFace(GL_CCW);
////////
////////	glBegin(GL_TRIANGLES);
////////	glColor3f(0.0f, 1.0f, 0.0f);
////////	glVertex3f(0, 60, 0);
////////	glColor3f(1.0f, 0.0f, 0.0f);
////////	glVertex3f(-60, -60, 0);
////////	glColor3f(0.0f, 0.0f, 1.0f);
////////	glVertex3f(60, -60, 0);
////////	glEnd();
////////	glPopMatrix();
////////	glutSwapBuffers(); 
////////}
////////
////////void SpecialKeys(int key, int x, int y)
////////{
////////	if(key == GLUT_KEY_UP) xRot-= 5.0f;
////////	if(key == GLUT_KEY_DOWN) xRot += 5.0f;
////////	if(key == GLUT_KEY_LEFT) yRot -= 5.0f;
////////	if(key == GLUT_KEY_RIGHT) yRot += 5.0f;
////////	if(xRot > 356.0f) xRot = 0.0f;
////////	if(xRot < -1.0f) xRot = 355.0f;
////////	if(yRot > 356.0f) yRot = 0.0f;
////////	if(yRot < -1.0f) yRot = 355.0f;
////////
////////	glutPostRedisplay();
////////}
////////void ProcessMenu(int value)
////////{
////////	switch(value)
////////	{
////////	case 1:
////////
////////		glPolygonMode(GL_FRONT,GL_FILL);
////////		break;
////////	case 2:
////////
////////		glPolygonMode(GL_FRONT,GL_LINE);
////////		break;
////////	case 3:
////////
////////		glPolygonMode(GL_FRONT,GL_POINT);
////////		break;
////////	case 4:
////////
////////		glPolygonMode(GL_FRONT,GL_FILL);
////////		break;
////////	case 5:
////////
////////		glPolygonMode(GL_FRONT,GL_LINE);
////////		break;
////////	case 6:
////////
////////		glPolygonMode(GL_FRONT,GL_POINT);
////////		break;
////////	case 7:
////////
////////		glShadeModel(GL_FLAT);
////////		break;
////////	case 8:
////////
////////		glShadeModel(GL_SMOOTH);
////////		break;
////////	case 9:
////////		bWinding = !bWinding;
////////		break;
////////	default:
////////		break;
////////	}
////////	glutPostRedisplay();
////////}
////////int main(int argc, char* argv[])
////////{
////////	int nModeMenu;
////////	int nMainMenu;
////////	int nColorMenu;
////////	glutInit(&argc, argv);
////////	glutInitDisplayMode(GLUT_DOUBLE | GLUT_RGB );
////////	glutCreateWindow("多边形演示");
////////	glutReshapeFunc(ChangeSize);
////////	glutSpecialFunc(SpecialKeys);  
////////	glutDisplayFunc(RenderScene);
////////
////////	nModeMenu = glutCreateMenu(ProcessMenu);
////////
////////	glutAddMenuEntry("正面多边形填充模式",1);
////////	glutAddMenuEntry("正面线框模型",2);
////////	glutAddMenuEntry("正面点模式",3);
////////	glutAddMenuEntry("反面多边形填充模式",4);
////////	glutAddMenuEntry("反面线框模型",5);
////////	glutAddMenuEntry("正面点模式反面",6);
////////
////////	nColorMenu = glutCreateMenu(ProcessMenu);
////////	glutAddMenuEntry("平面明暗模式?",7);
////////	glutAddMenuEntry("光滑明暗模式",8);
////////
////////	nMainMenu = glutCreateMenu(ProcessMenu);
////////	glutAddSubMenu("多边形模式", nModeMenu);
////////	glutAddSubMenu("颜色模式", nColorMenu);
////////	glutAddMenuEntry("改变绕法",9);
////////
////////	glutAttachMenu(GLUT_RIGHT_BUTTON);
////////	SetupRC();
////////	glutMainLoop();
////////	return 0;
////////}




////////////MoveRect.c
//////////#include <windows.h>
//////////#include <gl/glut.h>
//////////#include<gl/gl.h>
//////////#include<gl/glu.h>
//////////
//////////GLfloat x1 = 100.0f;
//////////GLfloat y1 = 150.0f;
//////////GLsizei rsize = 50;
//////////
//////////GLfloat xstep = 1.0f;
//////////GLfloat ystep = 1.0f;
//////////
//////////GLfloat windowWidth;
//////////GLfloat windowHeight;
//////////void RenderScene(void)
//////////{
//////////	glClear(GL_COLOR_BUFFER_BIT);
//////////	glColor3f(1.0f, 0.0f, 0.0f);
//////////	glRectf(x1, y1, x1+rsize, y1+rsize);
//////////
//////////	//glLineWidth();
//////////	glEnable(GL_LINE_STIPPLE);
//////////	glLineStipple(2,0x00ff);
//////////	glBegin(GL_TRIANGLES);
//////////		glShadeModel(GL_SMOOTH);
//////////		glColor3f(1.0f, 0.0f, 0.0f);
//////////		glVertex3f(0.0f,0.0f,0.0f);
//////////		glColor3f(0.0f, 1.0f, 0.0f);
//////////		glVertex3f(10.0f,100.0f,0.0f);
//////////		glColor3f(0.0f, 0.0f, 1.0f);
//////////		glVertex3f(200.0f, 0.0f,0.0f);
//////////	glEnd();
//////////
//////////	glutSwapBuffers();
//////////}
//////////void ChangeSize(GLsizei w, GLsizei h)
//////////{
//////////	if(h == 0) h = 1;
//////////	glViewport(0, 0, w, h);
//////////	glMatrixMode(GL_PROJECTION);
//////////	glLoadIdentity();
//////////	if (w <= h)
//////////	{
//////////		windowHeight = 250.0f*h/w;
//////////		windowWidth = 250.0f;
//////////	}
//////////	else
//////////	{
//////////		windowWidth = 250.0f*w/h;
//////////		windowHeight = 250.0f;
//////////	}
//////////	glOrtho(0.0f, windowWidth, 0.0f, windowHeight, 1.0f, -1.0f);
//////////	glMatrixMode(GL_MODELVIEW);
//////////	glLoadIdentity();
//////////}
//////////void TimerFunction(int value)
//////////{
//////////	//  
//////////	if(x1 > windowWidth-rsize || x1 < 0) xstep = -xstep;
//////////	if(y1 > windowHeight-rsize || y1 < 0) ystep = -ystep;
//////////	if(x1 > windowWidth-rsize) x1 = windowWidth-rsize-1;
//////////	if(y1 > windowHeight-rsize) y1 = windowHeight-rsize-1;
//////////	//  
//////////	x1 += xstep;
//////////	y1 += ystep;
//////////	//  
//////////	glutPostRedisplay();
//////////	glutTimerFunc(33,TimerFunction, 1);
//////////}
//////////void SetupRC(void)
//////////{
//////////	glClearColor(0.0f, 0.0f, 1.0f, 1.0f);
//////////}
//////////int main(void)
//////////{
//////////	glutInitDisplayMode(GLUT_DOUBLE | GLUT_RGB);
//////////	glutCreateWindow("Bounce");
//////////	glutDisplayFunc(RenderScene);
//////////	glutReshapeFunc(ChangeSize);
//////////	//glutTimerFunc(33, TimerFunction, 1);
//////////	SetupRC();
//////////	glutMainLoop();
//////////}





////////GLRect.c
//////#include <windows.h>
//////#include <gl/glut.h>
//////#include<gl/gl.h>
//////#include<gl/glu.h>
//////
//////void RenderScene(void)
//////{
//////	glClear(GL_COLOR_BUFFER_BIT);
//////	glColor3f(1.0f, 0.0f, 0.0f);
//////	glRectf(100.0f, 150.0f, 150.0f, 100.0f);
//////	glFlush();
//////}
//////
//////void ChangeSize(GLsizei w, GLsizei h)
//////{
//////	if(h == 0) h = 1;
//////
//////	glViewport(0, 0, w, h);
//////
//////	glMatrixMode(GL_PROJECTION);
//////	glLoadIdentity();
//////
//////	if (w <= h)
//////		glOrtho (0.0f, 250.0f, 0.0f, 250.0f*h/w, 1.0f, -1.0f);
//////	else
//////		glOrtho (0.0f, 250.0f*w/h, 0.0f, 250.0f, 1.0f, -1.0f);
//////	glMatrixMode(GL_MODELVIEW);
//////	glLoadIdentity();
//////}
//////
//////void SetupRC(void)
//////{
//////	glClearColor(1.0f, 1.0f, 1.0f, 0.0f);
//////}
//////
//////void main(void)
//////{
//////	glutInitDisplayMode(GLUT_SINGLE | GLUT_RGB);
//////
//////	glutCreateWindow("GLRect");
//////
//////	glutDisplayFunc(RenderScene);
//////	glutReshapeFunc(ChangeSize);
//////
//////	SetupRC();
//////
//////	glutMainLoop();
//////}