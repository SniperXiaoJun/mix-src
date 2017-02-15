#ifndef WATCH_H
#define WATCH_H

#include <QtGui/QMainWindow>
#include "pushbutton.h"
#include "ui_watch.h"
#include <QtGlobal>
#include <QTime>

class WATCH : public QMainWindow
{
	Q_OBJECT

public:
	WATCH(QWidget *parent = 0, Qt::WFlags flags = 0);
	~WATCH();
public slots:
	void pressSlot(PushButton *);

private:
	Ui::WATCHClass ui;
	PushButton label[100];
	QIcon icon [10];
	int score;
	PushButton * now;
};

#endif // WATCH_H
