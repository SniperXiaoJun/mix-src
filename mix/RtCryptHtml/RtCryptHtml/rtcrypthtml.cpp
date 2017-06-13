#include "rtcrypthtml.h"

#include <QMessageBox>
#include <QFileDialog>

RtCryptHtml::RtCryptHtml(QWidget *parent, Qt::WFlags flags)
	: QMainWindow(parent, flags)
{
	ui.setupUi(this);

	connect(ui.action_HTML_ImportPlain,SIGNAL(triggered()), this, SLOT(OpenPlainHtml()));
	connect(ui.action_HTML_ImportCipher,SIGNAL(triggered()), this, SLOT(OpenCipherHtml()));
	connect(ui.action_HTML_ExportPlain,SIGNAL(triggered()), this, SLOT(SavePlainHtml()));
	connect(ui.action_HTML_ExportCipher,SIGNAL(triggered()), this, SLOT(SaveCipherHtml()));

	connect(ui.actionShowPlain, SIGNAL(triggered()), this, SLOT(ShowPlainHtml()));
	connect(ui.actionOpenHTML,SIGNAL(triggered()), this, SLOT(OpenPlainHtml()));
	connect(ui.actionShowCipher,SIGNAL(triggered()), this, SLOT(ShowCipherHtml()));

	m_HtmlText = "<html><body><center>Hello!</center></body></html>";

	ui.webView->setHtml(m_HtmlText);

	edit = new QTextEdit(NULL);
}

RtCryptHtml::~RtCryptHtml()
{

}

QByteArray cipher2Plain(QByteArray ba)
{
	QString strRes = ba;

	QByteArray baRes = "";


	QStringList listPrefix = strRes.split("<body",QString::SkipEmptyParts,  Qt::CaseInsensitive);
	QStringList listSuffix = strRes.split("</body>",QString::SkipEmptyParts,  Qt::CaseInsensitive);


	if (listPrefix.size() != 2 || listSuffix.size() != 2)
	{
		return ba;
	}
	else
	{
		strRes = listPrefix.at(0);
		strRes += "<body";
		strRes += QByteArray::fromBase64(listPrefix.at(1).toUtf8());
		strRes += "</body>";
		strRes += listSuffix.at(1);
		return strRes.toUtf8();
	}

	//return QByteArray::fromBase64(ba);
}

QByteArray plain2Cipher(QByteArray ba)
{
	QString strRes = ba;

	QByteArray baRes = "";


	QStringList listPrefix = strRes.split("<body",QString::SkipEmptyParts,  Qt::CaseInsensitive);
	QStringList listSuffix = strRes.split("</body>",QString::SkipEmptyParts,  Qt::CaseInsensitive);


	if (listPrefix.size() != 2 || listSuffix.size() != 2)
	{
		return ba;
	}
	else
	{
		strRes = listPrefix.at(0);
		strRes += "<body";
		strRes += listPrefix.at(1).toUtf8().toBase64();
		strRes += "</body>";
		strRes += listSuffix.at(1);
		return strRes.toUtf8();
	}

	//return ba.toBase64();
}

void RtCryptHtml::OpenPlainHtml()
{
	QString fileName = QFileDialog::getOpenFileName();

	QFile file(fileName);
	if (!file.open(QIODevice::ReadOnly | QIODevice::Text))
		return;

	m_HtmlText = "";
	while (!file.atEnd()) {
		QByteArray line = file.readLine();
		m_HtmlText.append(line);
	}

	ui.webView->setHtml(m_HtmlText);
	//ui.webView->load(QUrl(fileName));
}

void RtCryptHtml::OpenCipherHtml()
{
	QString fileName = QFileDialog::getOpenFileName();

	QFile file(fileName);
	if (!file.open(QIODevice::ReadOnly | QIODevice::Text))
		return;

	m_HtmlText = "";
	while (!file.atEnd()) {
		QByteArray line = file.readLine();
		m_HtmlText.append(line);
	}

	ui.webView->setHtml(cipher2Plain(m_HtmlText));

	//ui.webView->load(QUrl(fileName));
}

void RtCryptHtml::SaveCipherHtml()
{
	QString fileName = QFileDialog::getSaveFileName();

	//QString str = ui.webView->selectedHtml();
	QFile file(fileName);
	if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
		return;

	QTextStream out(&file);
	out << plain2Cipher(m_HtmlText);
}

void RtCryptHtml::SavePlainHtml()
{
	QString fileName = QFileDialog::getSaveFileName();

	//QString str = ui.webView->selectedHtml();
	QFile file(fileName);
	if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
		return;

	QTextStream out(&file);
	out << m_HtmlText;
}

void RtCryptHtml::ShowPlainHtml()
{
	//QString str = ui.webView->selectedHtml();

	edit->setPlainText(m_HtmlText);

	edit->show();
}

void RtCryptHtml::ShowCipherHtml()
{
	//QString str = ui.webView->selectedHtml();

	edit->setPlainText(plain2Cipher(m_HtmlText));

	edit->show();
}
