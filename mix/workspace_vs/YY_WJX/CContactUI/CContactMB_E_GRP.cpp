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
    actionOpen->setText("打开");



    actionNewEGrp = new QAction(CContact);
    actionNewEGrp->setText("新增加密组");

    actionGrpWrite = new QAction(CContact);
    actionGrpWrite->setText("群发加密信息");

    actionReName = new QAction(CContact);
    actionReName->setText("重新命名");

    actionDel = new QAction(CContact);
    actionDel->setText("删除");

    actionSign_Cancel = new QAction(CContact);
    actionSign_Cancel->setText("标记/取消标记");

    actionRing = new QAction(CContact);
    actionRing->setText("默认铃声");

    actionRing_1 = new QAction(CContact);
    actionRing_1->setText("铃声1");

    actionRing_2 = new QAction(CContact);
    actionRing_2->setText("铃声2");


    actionSend = new QAction(CContact);
    actionSend->setText("发送本组联系人");
    
    actionExit = new QAction(CContact);
    actionExit->setText("退出");
    
    actionHelp = new QAction(CContact);
    actionHelp->setText("帮助");

	actionCopyTo = new QAction(CContact);
    actionCopyTo->setText("复制至非密组");

	actionCutTo = new QAction(CContact);
    actionCutTo->setText("剪切至非密组");

    
    menubar = new QMenuBar(CContact);
    menubar->setGeometry(QRect(0, 0, 240, 21));
    
    menu = new QMenu(menubar);
    menu->setTitle("菜单");
    
    menuMove = new QMenu(menu);
    menuMove->setTitle("移动本组");

	menuRing = new QMenu(menu);
    menuRing->setTitle("来电铃声");
    
    
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

