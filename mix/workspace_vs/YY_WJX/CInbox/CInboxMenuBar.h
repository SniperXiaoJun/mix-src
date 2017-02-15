/*
 * CInboxMenuBar.h
 *
 *  Created on: 2011-6-23
 *      Author: Administrator
 */

#ifndef CINBOXMENUBAR_H_
#define CINBOXMENUBAR_H_


#include <QMenuBar>
#include <QMenu>
#include <QAction>
#include <QMainWindow>


class CInboxMenuBar
{
public:
	CInboxMenuBar();
	virtual ~CInboxMenuBar();
	
	void setupMenuBar(QMainWindow *CInbox);
public:
    QAction *actionOpen;
    QAction *actionEdit;
    QAction *actionReply;
    QAction *actionDelete;
    QAction *actionHelp;
    QAction *actionExit;
    QAction *actionFold;
    QAction *action_A;
    QAction *action_B;
    QAction *action_C;
    QAction *actionSign;
    QAction *actionSignAll;
    QAction *actionCSign;
    QAction *actionCSignAll;
    QMenuBar *menubar;
    QMenu *menu;
    QMenu *menuMove;
    QMenu *menuSign;
};

#endif /* CINBOXMENUBAR_H_ */
