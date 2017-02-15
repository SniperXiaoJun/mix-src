#include "CContactMB.h"

CContactMB::CContactMB()
{

}

CContactMB::~CContactMB()
{

}

void CContactMB::setupMenuBar(QMainWindow *CContact)
{
    actionOpen = new QAction(CContact);
    actionOpen->setText("��");
   
    actionCall = new QAction(CContact);
    actionCall->setText("����");
    
    actionWrite = new QAction(CContact);
    actionWrite->setText("д������Ϣ");
    
    actionSign_Cancel = new QAction(CContact);
    actionSign_Cancel->setText("���/ȡ�����");
    
    actionSend = new QAction(CContact);
    actionSend->setText("������ϵ��");
    
    actionExit = new QAction(CContact);
    actionExit->setText("�˳�");
    
    actionHelp = new QAction(CContact);
    actionHelp->setText("����");

	actionCopyTo = new QAction(CContact);
    actionCopyTo->setText("���Ƶ�������ϵ��");

	actionCutTo = new QAction(CContact);
    actionCutTo->setText("���е�������ϵ��");

    
    menubar = new QMenuBar(CContact);
    menubar->setGeometry(QRect(0, 0, 240, 21));
    
    menu = new QMenu(menubar);
    menu->setTitle("�˵�");
    
    menuMove = new QMenu(menu);
    menuMove->setTitle("�ƶ���ϵ��");
    
    
    CContact->setMenuBar(menubar);

    menubar->addAction(menu->menuAction());
    menu->addAction(actionOpen);
    menu->addAction(actionCall);
    menu->addAction(actionWrite);
    menu->addAction(actionSign_Cancel);
	menu->addAction(actionSend);
    menu->addAction(menuMove->menuAction());
   
    menuMove->addAction(actionCopyTo);
	menuMove->addAction(actionCutTo);
	menu->addAction(actionHelp);
	menu->addAction(actionExit);
    
    
    QMetaObject::connectSlotsByName(CContact);
}
