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
    actionOpen->setText("打开");
   
    actionEdit = new QAction(CInbox);
    actionEdit->setText("写信息");
    
    actionReply = new QAction(CInbox);
    actionReply->setText("回复");
    
    actionDelete = new QAction(CInbox);
    actionDelete->setText("删除");
    
    actionHelp = new QAction(CInbox);
    actionHelp->setText("帮助");
    
    actionExit = new QAction(CInbox);
    actionExit->setText("退出");
    
    actionFold = new QAction(CInbox);
    actionFold->setText("加密文件夹");
    
    action_A = new QAction(CInbox);
    action_A->setText("子文件夹A");
    
    action_B = new QAction(CInbox);
    action_B->setText("子文件夹B");
    
    action_C = new QAction(CInbox);
    action_C->setText("子文件夹C");
    
    actionSign = new QAction(CInbox);
    actionSign->setText("标记");
    
    actionSignAll = new QAction(CInbox);
    actionSignAll->setText("标记全部");
    
    actionCSign = new QAction(CInbox);
    actionCSign->setText("取消标记");
    
    actionCSignAll = new QAction(CInbox);
    actionCSignAll->setText("全部取消标记");
    
    menubar = new QMenuBar(CInbox);
    menubar->setGeometry(QRect(0, 0, 240, 21));
    
    menu = new QMenu(menubar);
    menu->setTitle("菜单");
    
    menuMove = new QMenu(menu);
    menuMove->setTitle("移至加密文件夹");
    
    menuSign = new QMenu(menu);
    menuSign->setTitle("标记/取消标记");
    
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
