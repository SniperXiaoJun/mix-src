#include "CDiskSelectUI.h"
#include <QFileInfoList>
#include <QDir>
#include <QMessageBox>

CDiskSelectUI::CDiskSelectUI(QWidget *parent)
: QWidget(parent)
{
	ui.setupUi(this);
	connect(ui.pushButton_New, SIGNAL(clicked()), this , SLOT(SlotNew()));
	connect(ui.pushButton_Old, SIGNAL(clicked()), this , SLOT(SlotOld()));
}

CDiskSelectUI::~CDiskSelectUI()
{

}

int CDiskSelectUI::InitUI()
{
	ui.comboBox_New->clear();
	ui.comboBox_Old->clear();

	QFileInfoList fil = QDir::drives();
	for(int i=0;i<fil.size();++i)
	{
		QFileInfo fl=fil[i];
		qDebug(qPrintable(fl.filePath()));

		ui.comboBox_New->addItem(fl.filePath());
		ui.comboBox_Old->addItem(fl.filePath());
	}

	return 0;
}

void CDiskSelectUI::SlotNew()
{
	m_strNew = ui.comboBox_New->currentText();

	ui.label_New->setText(QString::fromLocal8Bit("�¿�:") + m_strNew);

	if(m_strNew == m_strOld)
	{
		QMessageBox::information(this, QString::fromLocal8Bit("��ʾ"), QString::fromLocal8Bit("���̷���ԭ�̷�һ��"));
	}
}

void CDiskSelectUI::SlotOld()
{
	m_strOld = ui.comboBox_Old->currentText();

	ui.label_Old->setText(QString::fromLocal8Bit("ԭ��:") + m_strOld);

	if(m_strNew == m_strOld)
	{
		QMessageBox::information(this, QString::fromLocal8Bit("��ʾ"), QString::fromLocal8Bit("���̷���ԭ�̷�һ��"));
	}
}

QString CDiskSelectUI::GetOld()
{
	return m_strOld;
}

QString CDiskSelectUI::GetNew()
{
	return m_strNew;
}