#include "CContactMB_E.h"

CContactMB_E::CContactMB_E()
{

}

CContactMB_E::~CContactMB_E()
{

}

void CContactMB_E::setupMenuBar(QMainWindow *CContact)
{
    actionNew = new QAction(CContact);
    actionNew->setText("����������ϵ��");


    actionOpen = new QAction(CContact);
    actionOpen->setText("��");
   
    actionCall = new QAction(CContact);
    actionCall->setText("����");
    
    actionWrite = new QAction(CContact);
    actionWrite->setText("д������Ϣ");

    actionDel = new QAction(CContact);
    actionDel->setText("ɾ����ϵ��");

	actionChg = new QAction(CContact);
    actionChg->setText("�޸���ϵ��");

	actionCurrentGrp = new QAction(CContact);
    actionCurrentGrp->setText("��ǰ��������");

    
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


	menuAddToEGrp = new QMenu(menu);
    menuAddToEGrp->setTitle("�������ܷ���");
	
    
    
    CContact->setMenuBar(menubar);

    menubar->addAction(menu->menuAction());
    menu->addAction(actionOpen);
    menu->addAction(actionCall);
    menu->addAction(actionWrite);
    menu->addAction(actionSign_Cancel);
	menu->addAction(actionSend);


	menu->addAction(actionNew);
	menu->addAction(actionChg);
	menu->addAction(actionDel);
	menu->addAction(actionCurrentGrp);


    menu->addAction(menuMove->menuAction());
	menu->addAction(menuAddToEGrp->menuAction());
   
    menuMove->addAction(actionCopyTo);
	menuMove->addAction(actionCutTo);
	menu->addAction(actionHelp);
	menu->addAction(actionExit);
    
    
    QMetaObject::connectSlotsByName(CContact);
}