#include "CContactMB_E_GRP.h"

CContactMB_E_GRP::CContactMB_E_GRP()
{

}

CContactMB_E_GRP::~CContactMB_E_GRP()
{

}



void CContactMB_E_GRP::setupMenuBar(QMainWindow *CContact)
{
    actionOpen = new QAction(CContact);
    actionOpen->setText("��");



    actionNewEGrp = new QAction(CContact);
    actionNewEGrp->setText("����������");

    actionGrpWrite = new QAction(CContact);
    actionGrpWrite->setText("Ⱥ��������Ϣ");

    actionReName = new QAction(CContact);
    actionReName->setText("��������");

    actionDel = new QAction(CContact);
    actionDel->setText("ɾ��");

    actionSign_Cancel = new QAction(CContact);
    actionSign_Cancel->setText("���/ȡ�����");

    actionRing = new QAction(CContact);
    actionRing->setText("Ĭ������");

    actionRing_1 = new QAction(CContact);
    actionRing_1->setText("����1");

    actionRing_2 = new QAction(CContact);
    actionRing_2->setText("����2");


    actionSend = new QAction(CContact);
    actionSend->setText("���ͱ�����ϵ��");
    
    actionExit = new QAction(CContact);
    actionExit->setText("�˳�");
    
    actionHelp = new QAction(CContact);
    actionHelp->setText("����");

	actionCopyTo = new QAction(CContact);
    actionCopyTo->setText("������������");

	actionCutTo = new QAction(CContact);
    actionCutTo->setText("������������");

    
    menubar = new QMenuBar(CContact);
    menubar->setGeometry(QRect(0, 0, 240, 21));
    
    menu = new QMenu(menubar);
    menu->setTitle("�˵�");
    
    menuMove = new QMenu(menu);
    menuMove->setTitle("�ƶ�����");

	menuRing = new QMenu(menu);
    menuRing->setTitle("��������");
    
    
    CContact->setMenuBar(menubar);

    menubar->addAction(menu->menuAction());
    menu->addAction(actionNewEGrp);
	menu->addAction(actionOpen);
    menu->addAction(actionGrpWrite);
    menu->addAction(actionReName);
    menu->addAction(actionDel);


	menu->addAction(menuRing->menuAction());

    menuRing->addAction(actionRing);
	menuRing->addAction(actionRing_1);
	menuRing->addAction(actionRing_2);


    menu->addAction(actionSign_Cancel);
    menu->addAction(actionSend);

    menu->addAction(menuMove->menuAction());
   
    menuMove->addAction(actionCopyTo);
	menuMove->addAction(actionCutTo);
	menu->addAction(actionHelp);
	menu->addAction(actionExit);
    
    
    QMetaObject::connectSlotsByName(CContact);

}

