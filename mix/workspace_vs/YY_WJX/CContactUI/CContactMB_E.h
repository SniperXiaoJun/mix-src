#ifndef CCONTACTMB_E_H
#define CCONTACTMB_E_H


#include <QMenuBar>
#include <QMenu>
#include <QAction>
#include <QMainWindow>
#include <QList>

class CContactMB_E
{
public:
	CContactMB_E();
	~CContactMB_E();

	void setupMenuBar(QMainWindow *CContact);

	QAction *actionNew;
    QAction *actionOpen;
    QAction *actionCall;
    QAction *actionWrite;
	QAction *actionChg;
	QAction *actionDel;
	QAction *actionCurrentGrp;

	QList<QAction *> actionList;

	QAction *actionSign_Cancel;
    QAction *actionSend;
    QAction *actionHelp;
    QAction *actionExit;
	QAction *actionCopyTo;
	QAction *actionCutTo;

    QMenuBar *menubar;
    QMenu *menu;
    QMenu *menuMove;
	QMenu *menuAddToEGrp;
	
};

#endif // CCONTACTMB_E_H
