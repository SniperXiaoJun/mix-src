#ifndef QT_TEST_H
#define QT_TEST_H

#include <QtGui/QMainWindow>
#include "ui_qt_test.h"
#include "../NetWorkCEDLL/NetWork.h"

#include "..\transaction\IReceiveCallBack.h"


class QT_Test : public QMainWindow, public IReceiveCallBack
{
	Q_OBJECT

public:
	QT_Test(QWidget *parent = 0, Qt::WFlags flags = 0);
	~QT_Test();

	void HandleReceiveData(const Byte *pMsg, u32 ulLen);
	virtual void HandleError(void);
	
public slots:

	void SlotSend();


private:
	Ui::QT_TestClass ui;

	CNetwork * m_pNetWork;
};

#endif // QT_TEST_H
