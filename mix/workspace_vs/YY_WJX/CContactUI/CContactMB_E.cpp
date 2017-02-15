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
    actionNew->setText("新增加密联系人");


    actionOpen = new QAction(CContact);
    actionOpen->setText("打开");
   
    actionCall = new QAction(CContact);
    actionCall->setText("呼叫");
    
    actionWrite = new QAction(CContact);
    actionWrite->setText("写加密信息");

    actionDel = new QAction(CContact);
    actionDel->setText("删除联系人");

	actionChg = new QAction(CContact);
    actionChg->setText("修改联系人");

	actionCurrentGrp = new QAction(CContact);
    actionCurrentGrp->setText("当前所属分组");

    
    actionSign_Cancel = new QAction(CContact);
    actionSign_Cancel->setText("标记/取消标记");
    
    actionSend = new QAction(CContact);
    actionSend->setText("发送联系人");
    
    actionExit = new QAction(CContact);
    actionExit->setText("退出");
    
    actionHelp = new QAction(CContact);
    actionHelp->setText("帮助");

	actionCopyTo = new QAction(CContact);
    actionCopyTo->setText("复制到非密联系人");

	actionCutTo = new QAction(CContact);
    actionCutTo->setText("剪切到非密联系人");

    
    menubar = new QMenuBar(CContact);
    menubar->setGeometry(QRect(0, 0, 240, 21));
    
    menu = new QMenu(menubar);
    menu->setTitle("菜单");
    
    menuMove = new QMenu(menu);
    menuMove->setTitle("移动联系人");


	menuAddToEGrp = new QMenu(menu);
    menuAddToEGrp->setTitle("增至加密分组");
	
    
    
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