#include "ctext.h"

CText::CText(QWidget *parent, Qt::WFlags flags)
	: QMainWindow(parent, flags)
{
	ui.setupUi(this);

	this->pfDialog = new QFileDialog();
	this->cdialog = new QColorDialog();
	
	connect(this->ui.pushButton,SIGNAL(clicked()),pfDialog,SLOT(open()));
	connect(pfDialog,SIGNAL(accepted()),this, SLOT(ADD()));
	connect(this->ui.pushButton_2,SIGNAL(clicked()),cdialog,SLOT(open()));
	connect(cdialog,SIGNAL(accepted()),this, SLOT(ADD2()));
}

CText::~CText()
{

}

void CText::ADD()
{
	QString htmlString;
	QString fileName;
	QString htmlFileName;

	fileName = pfDialog->selectedFiles().at(0);

	htmlFileName += QString("<img src = '");
	htmlFileName += fileName;
	htmlFileName += "'";
	htmlFileName += QString(">");


	this->ui.textEdit->textCursor().insertHtml(htmlFileName);
	this->ui.textEdit->textCursor().insertText(htmlFileName);
	this->ui.textEdit->textCursor().insertImage(fileName);
}


/*void CText::ADD()
{
	
	//static bool BoolValue = true;


	QString htmlString;
	QString fileName;
	QString htmlFileName;

	fileName = pfDialog->selectedFiles().at(0);
	//htmlString += this->ui.textEdit->toHtml();
	//htmlString += this->ui.textEdit->toPlainText();
	htmlFileName += QString("<img src = \"");
	htmlFileName += fileName;
	htmlFileName += "\"";
	htmlFileName += QString("/>");

	//htmlString += htmlFileName;

	/*this->ui.textEdit->setHtml(htmlString);

	if(BoolValue)
	{
		this->ui.textEdit->setText(htmlString);
		BoolValue = false;
	}
	else
	{
		BoolValue = true;
	}
	this->ui.textEdit->textCursor().insertHtml(htmlFileName);
}*/

void CText::ADD2()
{
	int a,b,c;
	QColor cc;
	cc = cdialog->currentColor();
	cc.getRgb( &a, &b, &c, NULL);
	char ss[100] = {0};
	sprintf(ss, "background-color: rgb(%3d,%3d,%3d)",a,b,c);
	this->setStyleSheet(QString::fromUtf8(ss));

	this->ui.textEdit->setTextColor(QColor(0,177,255));

	this->ui.textEdit->append(ss);
}
