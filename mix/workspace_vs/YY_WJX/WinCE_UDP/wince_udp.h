#ifndef WINCE_UDP_H
#define WINCE_UDP_H

#include <QtGui/QMainWindow>
#include "ui_wince_udp.h"

class WinCE_UDP : public QMainWindow
{
	Q_OBJECT

public:
	WinCE_UDP(QWidget *parent = 0, Qt::WFlags flags = 0);
	~WinCE_UDP();

private:
	Ui::WinCE_UDPClass ui;
};

#endif // WINCE_UDP_H
