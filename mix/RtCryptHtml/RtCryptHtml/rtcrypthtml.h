#ifndef RTCRYPTHTML_H
#define RTCRYPTHTML_H

#include <QtGui/QMainWindow>
#include <QtWebKit/QtWebKit>
#include <QTextEdit>

#include "ui_rtcrypthtml.h"

class RtCryptHtml : public QMainWindow
{
	Q_OBJECT

public:
	RtCryptHtml(QWidget *parent = 0, Qt::WFlags flags = 0);
	~RtCryptHtml();

public slots:

	void OpenPlainHtml();
	void OpenCipherHtml();
	void SavePlainHtml();
	void SaveCipherHtml();
	void ShowCipherHtml();
	void ShowPlainHtml();


private:
	Ui::RtCryptHtmlClass ui;
	QTextEdit * edit;
	QByteArray m_HtmlText;
};

#endif // RTCRYPTHTML_H
