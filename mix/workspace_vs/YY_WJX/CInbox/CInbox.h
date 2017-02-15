
#ifndef CINBOX_H
#define CINBOX_H

#include <QtGui/QMainWindow>
#include "ui_CInbox.h"

class CInbox : public QMainWindow
{
    Q_OBJECT

public:
	CInbox(QWidget *parent = 0);
    ~CInbox();
    
    
	void AddNewMsg(char * name = "10086", char * content = "Äãµç»°Ç··Ñ");

public slots:
	void SlotAddNewMsg();
	void SlotItemActivated(QListWidgetItem * item);
	void SetInformation(void *);
	void NoticeCtrl(void *);

private:
    Ui::CInbox ui;
	QListWidgetItem * m_pItem;
	QIcon m_Icon;
	QFont m_Font;
};

#endif // CINBOX_H
