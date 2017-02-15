#ifndef CCONTACTMB_GRP_H
#define CCONTACTMB_GRP_H



#include <QMenuBar>
#include <QMenu>
#include <QAction>
#include <QMainWindow>


class CContactMB_GRP
{
public:
	CContactMB_GRP();
	~CContactMB_GRP();

	void setupMenuBar(QMainWindow *CContact);
public:
	QAction *actionNewEGrp;
    QAction *actionOpen;
    QAction *actionGrpWrite;
	QAction *actionReName;
	QAction *actionDel;
    QAction *actionSign_Cancel;
    QAction *actionSend;
    QAction *actionHelp;
    QAction *actionExit;
	QAction *actionCopyTo;
	QAction *actionCutTo;
	QAction *actionRing;
	QAction *actionRing_1;
	QAction *actionRing_2;

    QMenuBar *menubar;
    QMenu *menu;
    QMenu *menuMove;
	QMenu *menuRing;
	
};

#endif // CCONTACTMB_GRP_H
