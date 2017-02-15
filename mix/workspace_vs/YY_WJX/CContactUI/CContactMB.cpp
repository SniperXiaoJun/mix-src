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
    actionOpen->setText("打开");
   
    actionCall = new QAction(CContact);
    actionCall->setText("呼叫");
    
    actionWrite = new QAction(CContact);
    actionWrite->setText("写加密信息");
    
    actionSign_Cancel = new QAction(CContact);
    actionSign_Cancel->setText("标记/取消标记");
    
    actionSend = new QAction(CContact);
    actionSend->setText("发送联系人");
    
    actionExit = new QAction(CContact);
    actionExit->setText("退出");
    
    actionHelp = new QAction(CContact);
    actionHelp->setText("帮助");

	actionCopyTo = new QAction(CContact);
    actionCopyTo->setText("复制到加密联系人");

	actionCutTo = new QAction(CContact);
    actionCutTo->setText("剪切到加密联系人");

    
    menubar = new QMenuBar(CContact);
    menubar->setGeometry(QRect(0, 0, 240, 21));
    
    menu = new QMenu(menubar);
    menu->setTitle("菜单");
    
    menuMove = new QMenu(menu);
    menuMove->setTitle("移动联系人");
    
    
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
