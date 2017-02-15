/*
 * CInboxMenuBar.cpp
 *
 *  Created on: 2011-6-23
 *      Author: Administrator
 */

#include "CInboxMenuBar.h"

CInboxMenuBar::CInboxMenuBar()
{


}

CInboxMenuBar::~CInboxMenuBar()
{
	
}

void CInboxMenuBar::setupMenuBar(QMainWindow *CInbox)
{
    actionOpen = new QAction(CInbox);
    actionOpen->setText("��");
   
    actionEdit = new QAction(CInbox);
    actionEdit->setText("д��Ϣ");
    
    actionReply = new QAction(CInbox);
    actionReply->setText("�ظ�");
    
    actionDelete = new QAction(CInbox);
    actionDelete->setText("ɾ��");
    
    actionHelp = new QAction(CInbox);
    actionHelp->setText("����");
    
    actionExit = new QAction(CInbox);
    actionExit->setText("�˳�");
    
    actionFold = new QAction(CInbox);
    actionFold->setText("�����ļ���");
    
    action_A = new QAction(CInbox);
    action_A->setText("���ļ���A");
    
    action_B = new QAction(CInbox);
    action_B->setText("���ļ���B");
    
    action_C = new QAction(CInbox);
    action_C->setText("���ļ���C");
    
    actionSign = new QAction(CInbox);
    actionSign->setText("���");
    
    actionSignAll = new QAction(CInbox);
    actionSignAll->setText("���ȫ��");
    
    actionCSign = new QAction(CInbox);
    actionCSign->setText("ȡ�����");
    
    actionCSignAll = new QAction(CInbox);
    actionCSignAll->setText("ȫ��ȡ�����");
    
    menubar = new QMenuBar(CInbox);
    menubar->setGeometry(QRect(0, 0, 240, 21));
    
    menu = new QMenu(menubar);
    menu->setTitle("�˵�");
    
    menuMove = new QMenu(menu);
    menuMove->setTitle("���������ļ���");
    
    menuSign = new QMenu(menu);
    menuSign->setTitle("���/ȡ�����");
    
    CInbox->setMenuBar(menubar);

    menubar->addAction(menu->menuAction());
    menu->addAction(actionOpen);
    menu->addAction(actionEdit);
    menu->addAction(actionReply);
    menu->addAction(actionDelete);
    menu->addAction(menuMove->menuAction());
    menu->addAction(menuSign->menuAction());
    menu->addAction(actionHelp);
    menu->addAction(actionExit);
    menuMove->addAction(actionFold);
    menuMove->addAction(action_A);
    menuMove->addAction(action_B);
    menuMove->addAction(action_C);
    menuSign->addAction(actionSign);
    menuSign->addAction(actionSignAll);
    menuSign->addAction(actionCSign);
    menuSign->addAction(actionCSignAll);
    
    
    QMetaObject::connectSlotsByName(CInbox);
}
