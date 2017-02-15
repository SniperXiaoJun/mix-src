#ifndef CCONTACTMB_H
#define CCONTACTMB_H

#include <QMenuBar>
#include <QMenu>
#include <QAction>
#include <QMainWindow>

class CContactMB
{
public:
	CContactMB();
	~CContactMB();

	void setupMenuBar(QMainWindow *CContact);
public:
    QAction *actionOpen;
    QAction *actionCall;
    QAction *actionWrite;
    QAction *actionSign_Cancel;
    QAction *actionSend;
    QAction *actionHelp;
    QAction *actionExit;
	QAction *actionCopyTo;
	QAction *actionCutTo;

    QMenuBar *menubar;
    QMenu *menu;
    QMenu *menuMove;
};

#endif // CCONTACTMB_H
