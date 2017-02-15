// bsipic.cpp: implementation of the bsipic class.
//程序设计：唐明理	2005.2
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
void bsipic::Point()//画点
{ glBegin(GL_POINTS);//
   glVertex3f( 0.0f, 1.0f,-1.0f);//a点
   glVertex3f(-1.0f,-1.0f, 0.0f);//b点
   glVertex3f( 1.0f,-1.0f, 0.0f);//c点

   glVertex3f( 0.0f, 0.0f, 0.0f);//中心
  glEnd();
}
void bsipic::Line()//画线
{ glBegin(GL_LINE_LOOP); //
   //glVertex3f( 0.0f, 1.0f,-1.0f);//a点
   //glVertex3f(-1.0f,-1.0f, 0.0f);//b点

   //glVertex3f( 0.0f, 1.0f,-1.0f);//a点
   //glVertex3f( 1.0f,-1.0f, 0.0f);//c点

   //glVertex3f(-1.0f,-1.0f, 0.0f);//b点
   //glVertex3f( 1.0f,-1.0f, 0.0f);//c点

   //glVertex3f( 0.0f, 1.0f,-1.0f);//a点
   //glVertex3f( 0.0f, 0.0f, 0.0f);//中心

   //glVertex3f(-1.0f,-1.0f, 0.0f);//b点
   //glVertex3f( 0.0f, 0.0f, 0.0f);//中心

   //glVertex3f( 1.0f,-1.0f, 0.0f);//c点
   //glVertex3f( 0.0f, 0.0f, 0.0f);//中心


	//glVertex3f( 2.0f, 2.0f, 2.0f);//中心
	glVertex3f( 1,0,-1);//中心
	//glVertex3f( 0.0f, 0.0f, 0.0f);//中心
	glVertex3f( -1,1,0);//中心
	//glVertex3f( 0.0f, 0.0f, 0.0f);//中心
	glVertex3f( 0,-1,1);//中心

  glEnd();
}
void bsipic::Triangle()//画面
{ glBegin(GL_POLYGON);//
	glVertex3f( 0.0f, 1.0f,-1.0f);//a点
	glVertex3f(-1.0f,-1.0f, 0.0f);//b点
	glVertex3f( 1.0f,-1.0f, 0.0f);//c点
  glEnd();
}
void bsipic::Square()//画正方面
{ glBegin(GL_POLYGON);//
	glVertex3f(0.0f,0.0f ,0.0f);//a点
	glVertex3f(1.0f,0.0f, 0.0f);//b点
	glVertex3f(1.0f,0.0f,-1.0f);//c点
	glVertex3f(0.0f,0.0f,-1.0f);//d点
  glEnd();
}
void bsipic::Esquare()//画正方体
{ glBegin(GL_QUAD_STRIP);//
    glVertex3f(0.0f,0.0f ,0.0f);//a0点
    glVertex3f(0.0f,1.0f ,0.0f);//a1点
    glVertex3f(1.0f,0.0f, 0.0f);//b0点
    glVertex3f(1.0f,1.0f, 0.0f);//b1点
    glVertex3f(1.0f,0.0f,-1.0f);//c0点
    glVertex3f(1.0f,1.0f,-1.0f);//c1点
    glVertex3f(0.0f,0.0f,-1.0f);//d0点
    glVertex3f(0.0f,1.0f,-1.0f);//d1点
    glVertex3f(0.0f,0.0f ,0.0f);//a0点
    glVertex3f(0.0f,1.0f ,0.0f);//a1点
  glEnd();

  glBegin(GL_POLYGON);//
	glVertex3f(0.0f,0.0f ,0.0f);//a0点
	glVertex3f(1.0f,0.0f, 0.0f);//b0点
	glVertex3f(1.0f,0.0f,-1.0f);//c0点
	glVertex3f(0.0f,0.0f,-1.0f);//d0点
	glVertex3f(0.0f,1.0f ,0.0f);//a1点
	glVertex3f(1.0f,1.0f, 0.0f);//b1点
	glVertex3f(1.0f,1.0f,-1.0f);//c1点
	glVertex3f(0.0f,1.0f,-1.0f);//d1点
  glEnd();
}
void bsipic::Park ()//画园
{ glBegin(GL_TRIANGLE_FAN);//
   glVertex3f(0,0,0.0f );   
   for(int i=0;i<=390;i+=30)
   {float p=(float)(i*3.14/180);
    glVertex3f((float)sin(p),(float)cos(p),0.0f );
   }
  glEnd();
}
void bsipic::Pillar () //园柱
{glBegin(GL_QUAD_STRIP);//
   for(int i=0;i<=390;i+=30)
   { float p=(float)(i*3.14/180);
	glVertex3f((float)sin(p)/2,(float)cos(p)/2,1.0f );
	glVertex3f((float)sin(p)/2,(float)cos(p)/2,0.0f );
   }
 glEnd();
}