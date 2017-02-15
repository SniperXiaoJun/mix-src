// bsipic.cpp: implementation of the bsipic class.
//������ƣ�������	2005.2
//E_mail cqtml@163.com
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "bsipic.h"

//////////////////////////////////////////////////////////////////////
bsipic::bsipic()
{

}

bsipic::~bsipic()
{

}
///////////////////////////////////////////////////////////////
void bsipic::Point()//����
{ glBegin(GL_POINTS);//
   glVertex3f( 0.0f, 1.0f,-1.0f);//a��
   glVertex3f(-1.0f,-1.0f, 0.0f);//b��
   glVertex3f( 1.0f,-1.0f, 0.0f);//c��

   glVertex3f( 0.0f, 0.0f, 0.0f);//����
  glEnd();
}
void bsipic::Line()//����
{ glBegin(GL_LINE_LOOP); //
   //glVertex3f( 0.0f, 1.0f,-1.0f);//a��
   //glVertex3f(-1.0f,-1.0f, 0.0f);//b��

   //glVertex3f( 0.0f, 1.0f,-1.0f);//a��
   //glVertex3f( 1.0f,-1.0f, 0.0f);//c��

   //glVertex3f(-1.0f,-1.0f, 0.0f);//b��
   //glVertex3f( 1.0f,-1.0f, 0.0f);//c��

   //glVertex3f( 0.0f, 1.0f,-1.0f);//a��
   //glVertex3f( 0.0f, 0.0f, 0.0f);//����

   //glVertex3f(-1.0f,-1.0f, 0.0f);//b��
   //glVertex3f( 0.0f, 0.0f, 0.0f);//����

   //glVertex3f( 1.0f,-1.0f, 0.0f);//c��
   //glVertex3f( 0.0f, 0.0f, 0.0f);//����


	//glVertex3f( 2.0f, 2.0f, 2.0f);//����
	glVertex3f( 1,0,-1);//����
	//glVertex3f( 0.0f, 0.0f, 0.0f);//����
	glVertex3f( -1,1,0);//����
	//glVertex3f( 0.0f, 0.0f, 0.0f);//����
	glVertex3f( 0,-1,1);//����

  glEnd();
}
void bsipic::Triangle()//����
{ glBegin(GL_POLYGON);//
	glVertex3f( 0.0f, 1.0f,-1.0f);//a��
	glVertex3f(-1.0f,-1.0f, 0.0f);//b��
	glVertex3f( 1.0f,-1.0f, 0.0f);//c��
  glEnd();
}
void bsipic::Square()//��������
{ glBegin(GL_POLYGON);//
	glVertex3f(0.0f,0.0f ,0.0f);//a��
	glVertex3f(1.0f,0.0f, 0.0f);//b��
	glVertex3f(1.0f,0.0f,-1.0f);//c��
	glVertex3f(0.0f,0.0f,-1.0f);//d��
  glEnd();
}
void bsipic::Esquare()//��������
{ glBegin(GL_QUAD_STRIP);//
    glVertex3f(0.0f,0.0f ,0.0f);//a0��
    glVertex3f(0.0f,1.0f ,0.0f);//a1��
    glVertex3f(1.0f,0.0f, 0.0f);//b0��
    glVertex3f(1.0f,1.0f, 0.0f);//b1��
    glVertex3f(1.0f,0.0f,-1.0f);//c0��
    glVertex3f(1.0f,1.0f,-1.0f);//c1��
    glVertex3f(0.0f,0.0f,-1.0f);//d0��
    glVertex3f(0.0f,1.0f,-1.0f);//d1��
    glVertex3f(0.0f,0.0f ,0.0f);//a0��
    glVertex3f(0.0f,1.0f ,0.0f);//a1��
  glEnd();

  glBegin(GL_POLYGON);//
	glVertex3f(0.0f,0.0f ,0.0f);//a0��
	glVertex3f(1.0f,0.0f, 0.0f);//b0��
	glVertex3f(1.0f,0.0f,-1.0f);//c0��
	glVertex3f(0.0f,0.0f,-1.0f);//d0��
	glVertex3f(0.0f,1.0f ,0.0f);//a1��
	glVertex3f(1.0f,1.0f, 0.0f);//b1��
	glVertex3f(1.0f,1.0f,-1.0f);//c1��
	glVertex3f(0.0f,1.0f,-1.0f);//d1��
  glEnd();
}
void bsipic::Park ()//��԰
{ glBegin(GL_TRIANGLE_FAN);//
   glVertex3f(0,0,0.0f );   
   for(int i=0;i<=390;i+=30)
   {float p=(float)(i*3.14/180);
    glVertex3f((float)sin(p),(float)cos(p),0.0f );
   }
  glEnd();
}
void bsipic::Pillar () //԰��
{glBegin(GL_QUAD_STRIP);//
   for(int i=0;i<=390;i+=30)
   { float p=(float)(i*3.14/180);
	glVertex3f((float)sin(p)/2,(float)cos(p)/2,1.0f );
	glVertex3f((float)sin(p)/2,(float)cos(p)/2,0.0f );
   }
 glEnd();
}