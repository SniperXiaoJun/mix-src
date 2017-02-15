#include "clineedit.h"
#include "stdio.h"
#include <QTextCodec>

CLineEdit::CLineEdit(unsigned char * p, QWidget *parent, Qt::WFlags flags)
	: QMainWindow(parent, flags)
{
	ui.setupUi(this);

	QTextCodec::setCodecForCStrings(QTextCodec::codecForName("UTF-8"));

	QRegExp regx("[-+<>0-9;]*$");
	QValidator *validator = new QRegExpValidator(regx,this);
			
	ui.lineEdit->setValidator( validator );

	connect(ui.pushButton, SIGNAL(clicked()), this ,SLOT(PrintSLOT()));
}

CLineEdit::~CLineEdit()
{
	
}

void CLineEdit::PrintSLOT()
{
	int numberList = 0;
	int i = 0;
	int j = 0;

	numberList = ui.lineEdit->text().count (QRegExp(";")) + 1;
	
	for(i = 0; i < numberList; i++)
	{
		if(ui.lineEdit->text().section(";",i,i) == QString())
		{
			continue;
		}

		m_StringList.append(ui.lineEdit->text().section(";",i,i));
		j++;
	}


	ui.lineEdit->setText(QString::number(m_StringList.count()));

	m_StringList.clear();

	//QString content = "asdgasdg<img src = 'icon.png' height='50' width='50'/>";
	//QString noImage = content.remove(QRegExp("<img src = .* height='50' width='50'/>"));

	//ui.lineEdit->insert(noImage);
}
