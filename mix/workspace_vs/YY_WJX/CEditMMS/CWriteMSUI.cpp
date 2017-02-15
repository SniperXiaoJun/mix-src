//-------------------------------------------------------------------------------------
// �ļ���: CWriteMSUI.cpp
// ������: Li Qiangqiang
// ��  ��: 2011-4-18
// ��  ��: ��ʵ�֣�ʵ����CWriteMSUI(�༭��Ϣ����)
// ��  ��: 1.0
//-------------------------------------------------------------------------------------
// �޸ļ�¼: 
// �� �� ��: 
// �޸�����: 
// �޸�Ŀ��: 
//-------------------------------------------------------------------------------------
#include "CWriteMSUI.h"
#include <QMessageBox>
#include <QFileDialog>
#include <QTextStream>
//////////////////////////////////////////////////////////////////////
// CWriteMSUI::CWriteMSUI(QWidget *parent, Qt::WFlags flags)
// ���������
// parent:
// flags:
// ���������
// ��
// ˵����
// ���캯��
// ����ֵ��
// ��
// ������
// 2011/4/18  ��ǿǿ
//////////////////////////////////////////////////////////////////////
CWriteMSUI::CWriteMSUI(QWidget *parent)
	: QMainWindow(parent)
{
	ui.setupUi(this);

	//m_pSMS = CSMSAdapter::NewL();
	//QRegExp regx("[-+()0-9;]*$");
	//QValidator *validator = new QRegExpValidator(regx,this);
	//ui.pReceiverLineEdit->setValidator( validator );
	//m_Fail = new CSendFailed();

	//connect(m_Fail,SIGNAL(ButtonClickedSignal(QStringList)),this,SLOT(SendAgain(QStringList)));

	bFlag = false;
	isMMS = false;

	iAddTextEditPos = 3;
	iNowPageNumber = 0;

	pmessageTextBrowser = this->ui.pmessagetextBrowser;
	pageList.append(pmessageTextBrowser);
	m_ImageName.append(QString());
	
	
#ifdef TOUCH_DISABLED
	this->ui.widget->hide();
#endif
	//QObject::connect(this->pmessageTextBrowser, SIGNAL(textChanged()), this, SLOT(TextChangeSlot()));


	QObject::connect(this->ui.pactionExit, SIGNAL(triggered()), this, SLOT(close()));
	QObject::connect(this->ui.pactionAddPage, SIGNAL(triggered()), this, SLOT(AddPage()));
	QObject::connect(this->ui.pactionInsertImage, SIGNAL(triggered()), this, SLOT(InsertImage()));
	QObject::connect(this->ui.pactionDelPage, SIGNAL(triggered()), this, SLOT(DelPage()));
	QObject::connect(this->ui.pactionSave, SIGNAL(triggered()), this, SLOT(SaveMessage()));
	QObject::connect(this->ui.pactionNext, SIGNAL(triggered()), this, SLOT(NextPage()));
	QObject::connect(this->ui.pactionBack, SIGNAL(triggered()), this, SLOT(BackPage()));
	QObject::connect(this->ui.pushButtonNext, SIGNAL(clicked()), this, SLOT(NextPage()));
	QObject::connect(this->ui.pushButtonBack, SIGNAL(clicked()), this, SLOT(BackPage()));
	QObject::connect(this->ui.pactionAddUser,SIGNAL(triggered()),this,SLOT(AddUser()));
	QObject::connect(this->ui.pactionSend, SIGNAL(triggered()), this, SLOT(SendSlot()));
	
	
	ui.pSenderLineEdit->setFocus();
}


//////////////////////////////////////////////////////////////////////
// CWriteMSUI::~CWriteMSUI()
// ���������
// ��
// ���������
// ��
// ˵����
// ��������
// ����ֵ��
// ��
// ������
// 2011/4/18  ��ǿǿ
//////////////////////////////////////////////////////////////////////
CWriteMSUI::~CWriteMSUI()
{
	//delete m_Fail;
}

//////////////////////////////////////////////////////////////////////
// void CWriteMSUI::AddPage()
// ���������
// ��
// ���������
// ��
// ˵����
// ʵ�����ҳ(��)
// ����ֵ��
// ��
// ������
// 2011/4/18 ��ǿǿ
//////////////////////////////////////////////////////////////////////
void CWriteMSUI::AddPage()
{
	int i;

	for (i = 0; i < pageList.length(); i++)
	{
		pageList.at(i)->hide();
	}

	pmessageTextBrowser = new QTextBrowser(this->ui.scrollArea);
	pmessageTextBrowser->setReadOnly(false);

	pmessageTextBrowser->setStyleSheet(QString::fromUtf8("border-image: url(:/mmspic/mmspic/editcenter.png)"));

	QObject::connect(this->pmessageTextBrowser, SIGNAL(textChanged()), this, SLOT(TextChangeSlot()));
	
	
	this->ui.gridLayout_2->addWidget(pmessageTextBrowser, iAddTextEditPos, 0, 1, 2);

	pageList.append(pmessageTextBrowser);
	m_ImageName.append(QString());
	iNowPageNumber = pageList.count() - 1;

	this->ui.labelPage->setText(QString().number(iNowPageNumber + 1) + "/" + QString().number(pageList.count()));


	pmessageTextBrowser->show();
	
	pmessageTextBrowser->setFocus();
}

//////////////////////////////////////////////////////////////////////
// void CWriteMSUI::DelPage()
// ���������
// ��
// ���������
// ��
// ˵����
// ʵ��ɾ��ҳ(��)
// ����ֵ��
// ��
// ������
// 2011/4/18 ��ǿǿ
//////////////////////////////////////////////////////////////////////
void CWriteMSUI::DelPage()
{
	int inumberML = pageList.count();


	if (1 == inumberML)
	{
  		QMessageBox::warning(0, QString::fromLocal8Bit("����"),
  			QString::fromLocal8Bit( "��һҳ!"),
			QMessageBox::Close);
		return ;// ֻ��һҳ��ɾ��
	}

	//for (i = 0; i < inumberML; i++)
	//{
	//	QWidget * pWidget = this->focusWidget();
	//	

	//	if (pageList.at(i) == qobject_cast<QTextEdit *>(pWidget )) 
	//	{ 
	//		pmessageTextBrowser = pageList.at(i);
	//		pageList.removeAt(i);
	//		delete pmessageTextBrowser;
	//		pmessageTextBrowser = NULL;
	//		break;
	//	}
	//}

	pmessageTextBrowser = pageList.at(iNowPageNumber);
	pageList.removeAt(iNowPageNumber);
	m_ImageName.removeAt(iNowPageNumber);
	delete pmessageTextBrowser;
	pmessageTextBrowser = NULL;

	this->NextPage();
	this->ui.labelPage->setText(QString().number(iNowPageNumber + 1) + "/" + QString().number(pageList.count()));

	pmessageTextBrowser = pageList.at(iNowPageNumber);
	pmessageTextBrowser->setFocus();
}

//////////////////////////////////////////////////////////////////////
// void CWriteMSUI::InsertImage()
// ���������
// ��
// ���������
// ��
// ˵����
// ʵ�ֲ���ͼƬ(��)
// ����ֵ��
// ��
// ������
// 2011/4/18 ��ǿǿ
//////////////////////////////////////////////////////////////////////
void CWriteMSUI::InsertImage()
{
	QString htmlFileName;

	pmessageTextBrowser = pageList.at(iNowPageNumber);

	if(pmessageTextBrowser->toHtml().contains("img src="))
	{
		QMessageBox::warning(this, QString::fromLocal8Bit("����"),
			QString::fromLocal8Bit( "��ҳ�Ѿ�����ͼƬ!"),
			QMessageBox::Close);

		return;
	}

	////for (i = 0; i < inumberML; i++)
	////{
	////	QWidget * pWidget = this->focusWidget();

	////	if (pageList.at(i) == qobject_cast<QTextEdit *>(pWidget )) 
	////	{
	////		pmessageTextBrowser = pageList.at(i);
	////		break ;
	////	}
	////}

	////
	////if (NULL == pmessageTextBrowser)
	////{
	////	errorMessage.showMessage("The Cursor is't in TextEdit!");
	////	return ;
	////}


	QString fileName = QFileDialog::getOpenFileName(this,tr("Open File"),
	                   "/",tr("Images (*.png *.xpm *.bmp *.jpg)"));

	htmlFileName += QString("<img src= '");
	htmlFileName += fileName;
	htmlFileName += "'";
	htmlFileName += QString(" height='50' width='50'/>");

	if(fileName != QString())
	{
		this->pmessageTextBrowser->textCursor().insertHtml(htmlFileName);
		m_ImageName.removeAt(iNowPageNumber);
		m_ImageName.insert(iNowPageNumber, fileName);
	}

	pmessageTextBrowser->setFocus();
}

//////////////////////////////////////////////////////////////////////
// void CWriteMSUI::SaveMessage()
// ���������
// ��
// ���������
// ��
// ˵����
// ʵ�ֱ�����Ϣ(��)
// ����ֵ��
// ��
// ������
// 2011/4/18 ��ǿǿ
//////////////////////////////////////////////////////////////////////
void CWriteMSUI::SaveMessage()
{
	//{
	//	SImg img;
 //		STxt txt;
	//	////SAud aud = {"1.mp3"};
	//	////Char *pStrDurTime = "3000ms";
	//	QString textFileName = "../" + QString::number(i + 1) + ".txt";
	//	QFile textFile(textFileName);

	//	if (!textFile.open(QIODevice::WriteOnly))
	//	{
	//		return;
	//	}
	//	QTextStream out(&textFile);


	//	textBrower.setHtml(pageList.at(i)->toHtml().remove(QRegExp("<img src=.*/>")));

	//	out<<textBrower.toPlainText();
	//	textFile.close();

	//	

	//	QFile imgFile(m_ImageName.at(i));
	//	QString imageFileName;

	//	if(m_ImageName.at(i) != QString())
	//	{
	//		imageFileName = QString::number(i + 1) + "." + m_ImageName.at(i).section('.', -1);
	//		imgFile.copy(imageFileName);
	//	}

	//	memset(txt.szName, 0, FILENAMELEN);
	//	memcpy(txt.szName, textFileName.toAscii().data(), textFileName.count());
	//	memset(img.szName, 0, FILENAMELEN);
	//	memset(img.szHeight, 0, FILENAMELEN);
	//	memset(img.szWidth, 0, FILENAMELEN);
	//	memcpy(img.szName, imageFileName.toAscii().data(), imageFileName.count());
	//	memcpy(img.szHeight, "100", 4);
	//	memcpy(img.szWidth, "100", 4);

	//	makeSmil.AddSmilPage(&img, &txt);
	//}

	//char *strSmil = new char[4096];
 //	memset(strSmil, 0, 4096);
 //	makeSmil.FormSmil(strSmil);

 //	if (TE_OK != makeSmil.Save("HtmlToSmil.xml"))
 //	{
 //		QMessageBox::warning(this, QString::fromLocal8Bit("֪ͨ"),
	//		QString::fromLocal8Bit( "����ʧ��!"),
	//		QMessageBox::Close);
 //	}
	//else
	//{
 //		QMessageBox::warning(this, QString::fromLocal8Bit("֪ͨ"),
	//		QString::fromLocal8Bit( "����ɹ�!"),
	//		QMessageBox::Close);
	//}

	//////{
	//////QString fileName = QFileDialog::getSaveFileName(this, tr("Save File"),
	//////	"noname.html",
	//////	tr("HTML files (*.html)"));
	//////QFile file(fileName);
	//////int i = 0;
	//////int inumberML = pageList.count();

	//////if (!file.open(QIODevice::WriteOnly))
	//////{
	//////	return;
	//////}

	//////QTextStream out(&file);
	//////
	//////for (i = 0; i < inumberML; i++)
	//////{
	//////	//out<<"<p ";
	//////	//out<<pageList.at(i)->toHtml().section("<p ",1,1).section("</p>",0,0);
	//////	//out<<"</p>";	
	//////	out<<pageList.at(i)->toHtml();
	//////}

	//////file.close();
	//////}
	//ui.pSenderLineEdit->setFocus();
}

//////////////////////////////////////////////////////////////////////
// void CWriteMSUI::NextPage()
// ���������
// ��
// ���������
// ��
// ˵����
// ʵ����һҳ(��)
// ����ֵ��
// ��
// ������
// 2011/4/18 ��ǿǿ
//////////////////////////////////////////////////////////////////////
void CWriteMSUI::NextPage()
{
	int i;
	int inumberML = pageList.count();

	for (i = 0; i < pageList.length(); i++)
	{
		pageList.at(i)->hide();
	}
	
	iNowPageNumber++;
	iNowPageNumber = iNowPageNumber%inumberML;
	pageList.at(iNowPageNumber)->show();

	this->ui.labelPage->setText(QString().number(iNowPageNumber + 1) + "/" + QString().number(pageList.count()));
	ui.pSenderLineEdit->setFocus();
}

//////////////////////////////////////////////////////////////////////
// void CWriteMSUI::BackPage()
// ���������
// ��
// ���������
// ��
// ˵����
// ʵ����һҳ(��)
// ����ֵ��
// ��
// ������
// 2011/4/18 ��ǿǿ
//////////////////////////////////////////////////////////////////////
void CWriteMSUI::BackPage()
{
	int i;
	int inumberML = pageList.count();

	for (i = 0; i < pageList.length(); i++)
	{
		pageList.at(i)->hide();
	}

	iNowPageNumber = iNowPageNumber + inumberML - 1;
	iNowPageNumber = iNowPageNumber%inumberML;
	pageList.at(iNowPageNumber)->show();
	this->ui.labelPage->setText(QString().number(iNowPageNumber + 1) + "/" + QString().number(pageList.count()));
	ui.pSenderLineEdit->setFocus();
}


//////////////////////////////////////////////////////////////////////
// void CWriteMSUI::AddUser()
// ���������
// ��
// ���������
// ��
// ˵����
// �����ϵ��(��)
// ����ֵ��
// ��
// ������
// 2011/4/18 ��ǿǿ
//////////////////////////////////////////////////////////////////////
void CWriteMSUI::AddUser()
{
	//int iRet = 0;
	//wchar_t gpszRecipient[15] = {0};

	//iRet = m_pInterFace->GetContacts(gpszRecipient);

	//if (iRet != 0)
	//{
	//	QMessageBox::warning(this, QString::fromLocal8Bit("֪ͨ"),
	//		QString::fromLocal8Bit( "����ռ���ʧ��!"),
	//		QMessageBox::Retry);
	//}
	//else
	//{
	//	if (ui.pReceiverLineEdit->text() == "")
	//	{
	//		ui.pReceiverLineEdit->insert(QString::fromUtf16((ushort*)gpszRecipient));
	//		repaint();
	//	} 
	//	else
	//	{
	//		ui.pReceiverLineEdit->insert(QString::fromLocal8Bit(";"));
	//		ui.pReceiverLineEdit->insert(QString::fromUtf16((ushort*)gpszRecipient));
	//		repaint();
	//	}
	//}
}

//////////////////////////////////////////////////////////////////////
// void CWriteMSUI::SendSlot()
// ���������
// ��
// ���������
// ��
// ˵����
// ������Ͳ˵��Ĳۺ���
// ����ֵ��
// ��
// ������
// 2011/4/18  ��ǿǿ
//////////////////////////////////////////////////////////////////////
void CWriteMSUI::SendSlot()
{
	if(ui.pThemeLineEdit->text() == QString() && pageList.count() == 1)
	{
		if(pmessageTextBrowser->toHtml().contains("img src=",Qt::CaseInsensitive))
		{
			isMMS = true;
		}
		else
		{
			isMMS = false;
		}
	}
	else
	{
		isMMS = true;
	}



	m_IncorrectNumber = QStringList();
	
	int numberList = 0;
	int i = 0;
	QStringList m_SendList;

	numberList = ui.pReceiverLineEdit->text().count (QRegExp(";")) + 1;

	for(i = 0; i < numberList; i++)
	{
		if(ui.pReceiverLineEdit->text().section(";",i,i) == QString())
		{
			continue;
		}
		else
		{
			QString number = ui.pReceiverLineEdit->text().section(";",i,i);
			if(0 == number.count("(") && 0 == number.count(")"))
			{
				if(number.count() > 10)
				{
				//	number = number.right(11);
					m_SendList.append(number);
				}
				else
				{
					m_IncorrectNumber.append(number);
				}
			}
			else if(1 == number.count("(") && 1 == number.count(")"))
			{
				number = number.section("(",1,1);
				number = number.section(")",0,0);

				if(number.count() > 10)
				{
					number = number.right(11);
					m_SendList.append(number);
				}
				else
				{
					m_IncorrectNumber.append(number);
				}
			}
			else
			{
				m_IncorrectNumber.append(number);
			}
		}
	}
	if(isMMS)
	{
		int iRet = SendMMS(m_SendList.at(0));
	}
	else
	{
		//int iRet = SendSMS(m_SendList);
	int iRet = SendMMS(m_SendList.at(0));
	}
}

//////////////////////////////////////////////////////////////////////
// int CWriteMSUI::SendMMS(QStringList stringList)
// ���������
// stringList:
// �ֻ������б�
// ���������
// ��
// ˵����
// �෢����
// ����ֵ��
// int
// ������
// 2011/4/18 ��ǿǿ
//////////////////////////////////////////////////////////////////////
int CWriteMSUI::SendMMS(QStringList stringList)
{
	QMessageBox::warning(this, QString::fromLocal8Bit("֪ͨ"),
		QString::fromLocal8Bit( "���Ź���δʵ�֣�"),
		QMessageBox::Close);

	return 0;
}


//////////////////////////////////////////////////////////////////////
// int CWriteMSUI::SendSMS(QStringList stringList)
// ���������
// stringList:
// �ֻ������б�
// ���������
// ��
// ˵����
// �෢����
// ����ֵ��
// int
// ������
// 2011/4/18  ��ǿǿ
//////////////////////////////////////////////////////////////////////
//-------------------------------------------------------------------------------------
// �޸ļ�¼: 
// �� �� ��: ˧����
// �޸�����: 2011-06-16
// �޸�Ŀ��: ����ʵ��SendSMS����
//-------------------------------------------------------------------------------------
int CWriteMSUI::SendSMS(QStringList stringList)
{
	int i = 0;
	int ret = 0;
	int strListLen = stringList.count();

	QStringList unSuccessList;
	
	for( i = 0; i < strListLen; i++)
	{
		ret = SendSMS(stringList.at(i));
		if(0 == ret)
		{
			QMessageBox::information(0, QString::fromLocal8Bit("֪ͨ"),
				QString::fromLocal8Bit( "Msg Sent Succeed!"),
				QMessageBox::Ok);
			//this->close();
		}
		else
		{
		QMessageBox::information(0, QString::fromLocal8Bit("֪ͨ"),
					QString::fromLocal8Bit( "Msg Sent Failed!"),
					QMessageBox::Ok);
			//unSuccessList.append(m_IncorrectNumber);
			//m_Fail->SetCSendFailed(unSuccessList);
			//m_Fail->exec();
		}
		if(-1 == ret)    //ʧ��
		{
			return 0;
		}
		else if(0 == ret)//�ɹ�
		{
			
		}
		else             //����
		{
			unSuccessList.append(stringList.at(i));
		}
	}

	if(0 == unSuccessList.count() && 0 == m_IncorrectNumber.count())
	{
		this->close();
	}
	else
	{
		unSuccessList.append(m_IncorrectNumber);
		//m_Fail->SetCSendFailed(unSuccessList);
		//m_Fail->exec();
	}

	return 0;
}


//////////////////////////////////////////////////////////////////////
// int CWriteMSUI::SendMMS(QString numberString)
// ���������
// numberString:
// �ֻ�����
// ���������
// ��
// ˵����
// ���Ͳ���
// ����ֵ��
// int
// ������
// 2011/4/18  ��ǿǿ
//////////////////////////////////////////////////////////////////////
int CWriteMSUI::SendMMS(QString numberString)
{
	m_TextName.clear();
	char pInputNum[16] = {0};

	int iLenRecipient = strlen(numberString.toAscii().constData());
	
	memcpy(pInputNum,numberString.toAscii().data(), iLenRecipient);
	
	char theme[20] = {0};
	memcpy(theme,ui.pThemeLineEdit->text().toAscii().data(), 20);
	

	QTextBrowser textBrower;
	int i = 0;
	int inumberML = pageList.count();

	for(i = 0; i < inumberML; i++)
	{
		QString textFileName = QString::number(i + 1) + ".txt";
		QFile textFile(textFileName);
		
		m_TextName.append(textFileName);

		if (!textFile.open(QIODevice::WriteOnly))
		{
			return -1;
		}
		QTextStream out(&textFile);

		textBrower.setHtml(pageList.at(i)->toHtml().remove(QRegExp("<img src=.*/>")));

		out<<textBrower.toPlainText();
		textFile.close();
	}

	CArg arg;

	arg.SetType(0);

	arg.SetCode(2 * inumberML);
	
	arg.SetPointer(1, pInputNum);

	arg.SetPointer(2, theme);
	char ** p = new (char * [inumberML * 2]); 
	char ** q ;
	q = p;
	
	for(int j = 0; j < inumberML; j++)
	{
		char  * imgFile = new char[100];
		char * txtFile = new char[100];
		
		memset(imgFile, 0, 100);
		memset(imgFile, 0, 100);
		
		char * txt = ".txt";
		char * img = "";
		
		memcpy(imgFile,m_ImageName.at(j).toAscii().constData(),strlen(m_ImageName.at(j).toAscii().constData()) + 1);
		memcpy(txtFile,m_TextName.at(j).toAscii().constData(),strlen(m_TextName.at(j).toAscii().constData()) + 1);

		*p = txtFile;
		p++;
		*p = imgFile;
		p++;
	}
	
	arg.SetPointer(3, (void *)q);
	
	arg.SetPointer(4, theme);



	NotifyObserver(&arg);
	//int iRet = m_pSMS->SendShortMessageL(pInputNum, pInput);

	return 0;

}

//////////////////////////////////////////////////////////////////////
// int CWriteMSUI::SendSMS(QString numberString)
// ���������
// numberString:
// �ֻ����봮
// ���������
// ��
// ˵����
// ���Ͷ���
// ����ֵ��
// int
// ������
// 2011/5/27  ˧����
//////////////////////////////////////////////////////////////////////
//-------------------------------------------------------------------------------------
// �޸ļ�¼: 
// �� �� ��: ˧����
// �޸�����: 2011-06-16
// �޸�Ŀ��: ���뷢���Ź���ʵ��
//-------------------------------------------------------------------------------------

int CWriteMSUI::SendSMS(QString numberString)
{
	//pmessageTextBrowser = pageList.at(iNowPageNumber);
	char pInputNum[16] = {0};
	//wchar_t pwInputNum[16] = {0};
	int iLenRecipient = strlen(numberString.toAscii().constData());
	memcpy(pInputNum,numberString.toAscii().data(), iLenRecipient);
	//QString QInput = ;
	int iLenInput = pmessageTextBrowser->toPlainText().length();
	char *pInput = new char[iLenInput*2+2];
	memset(pInput, 0, iLenInput*2+2);
	memcpy(pInput, (char *)pmessageTextBrowser->toPlainText().utf16(), iLenInput*2);

	CArg arg;
	arg.SetType(0);
	arg.SetPointer(1, pInputNum);
	arg.SetLength(1, iLenRecipient);
	arg.SetPointer(2, pInput);
	arg.SetLength(2, iLenInput);
	NotifyObserver(&arg);
	//int iRet = m_pSMS->SendShortMessageL(pInputNum, pInput);

	return 0;
}

//////////////////////////////////////////////////////////////////////
// void CWriteMSUI::SendAgain(QStringList stringList)
// ���������
// stringList:
// ����ʧ�ܺ����б�
// ���������
// ��
// ˵����
// �ٴη���
// ����ֵ��
// ��
// ������
// 2011/4/18  ��ǿǿ
//////////////////////////////////////////////////////////////////////
void CWriteMSUI::SendAgain(QStringList stringList)
{
	//m_Fail->hide();
	if(isMMS)
	{
		SendMMS(stringList);

	}
	else
	{
		SendSMS(stringList);
	}
}


//void CWriteMSUI::GetMailInterFace(CMailUtilityObserver *pMailInterFace)
//{
//	m_pInterFace = pMailInterFace;
//}


void CWriteMSUI::TextChangeSlot()
{
	if(pageList.at(iNowPageNumber)->toHtml().contains("img src=",Qt::CaseInsensitive))
	{
		return;
	}
	else
	{
		m_ImageName.removeAt(iNowPageNumber);
		m_ImageName.insert(iNowPageNumber, QString());
	}
}


//////////////////////////////////////////////////////////////////////
// void CWriteMSUI::NotifyObserver()
// ���������
// ��
// ���������
// ��
// ˵����
// �۲���֪ͨ
// ����ֵ��
// ��
// ������
// 2011/4/18 ��ǿǿ
//////////////////////////////////////////////////////////////////////
//-------------------------------------------------------------------------------------
// �޸ļ�¼: 
// �� �� ��: ˧����
// �޸�����: 2011-06-15
// �޸�Ŀ��: ʵ��NotifyObserver(CArg *pData)����
//-------------------------------------------------------------------------------------
void CWriteMSUI::NotifyObserver(CArg *pData)
{
	char *p ;
	
	p = *(char **)(pData->GetPointer(3));

		//ProcessESMSFunc((Byte*) pArg->GetPointer(1), pArg->GetLength(1),
		//		(Byte*) pArg->GetPointer(2), pArg->GetLength(2));
}

//////////////////////////////////////////////////////////////////////
// void CWriteMSUI::RegisterObserver()
// ���������
// ��
// ���������
// ��
// ˵����
// ע��۲���
// ����ֵ��
// ��
// ������
// 2011/4/18 ��ǿǿ
//////////////////////////////////////////////////////////////////////
//-------------------------------------------------------------------------------------
// �޸ļ�¼: 
// �� �� ��: ˧����
// �޸�����: 2011-06-15
// �޸�Ŀ��: ʵ��Puk�����ܺ���
//-------------------------------------------------------------------------------------


//////////////////////////////////////////////////////////////////////
// void CWriteMSUI::ShowUI()
// ���������
// ��
// ���������
// ��
// ˵����
// ��ʾ
// ����ֵ��
// ��
// ������
// 2011/4/18 ��ǿǿ
//////////////////////////////////////////////////////////////////////
void CWriteMSUI::ShowUI()
{
	this->show();
}

//////////////////////////////////////////////////////////////////////
//void CWriteMSUI::ShowFullScreenUI()
// ���������
// ��
// ���������
// ��
// ˵����
// ȫ����ʾ
// ����ֵ��
// ��
// ������
// 2011/4/18 ��ǿǿ
//////////////////////////////////////////////////////////////////////
void CWriteMSUI::ShowFullScreenUI()
{
	this->showFullScreen();
}

//////////////////////////////////////////////////////////////////////
// void CWriteMSUI::ShowMaximizedUI()
// ���������
// ��
// ���������
// ��
// ˵����
// ���
// ����ֵ��
// ��
// ������
// 2011/4/18 ��ǿǿ
//////////////////////////////////////////////////////////////////////
void CWriteMSUI::ShowMaximizedUI()
{
	this->showMaximized();
}

//////////////////////////////////////////////////////////////////////
// void CWriteMSUI::ShowMinimizedUI()
// ���������
// ��
// ���������
// ��
// ˵����
// ��С��
// ����ֵ��
// ��
// ������
// 2011/4/18 ��ǿǿ
//////////////////////////////////////////////////////////////////////
void CWriteMSUI::ShowMinimizedUI()
{
	this->showMinimized();
}

//////////////////////////////////////////////////////////////////////
// void CWriteMSUI::HideUI()
// ���������
// ��
// ���������
// ��
// ˵����
// ����
// ����ֵ��
// ��
// ������
// 2011/4/18 ��ǿǿ
//////////////////////////////////////////////////////////////////////
void CWriteMSUI::HideUI()
{
	this->hide();
}

//////////////////////////////////////////////////////////////////////
// void CWriteMSUI::CloseUI()
// ���������
// ��
// ���������
// ��
// ˵����
// �ر�
// ����ֵ��
// ��
// ������
// 2011/4/18 ��ǿǿ
//////////////////////////////////////////////////////////////////////
void CWriteMSUI::CloseUI()
{
	this->close();
}

//////////////////////////////////////////////////////////////////////
// void CWriteMSUI::closeEvent(QCloseEvent *event)
// ���������
// QCloseEvent *event ��QT�ر��¼�
// ���������
// ��
// ˵����
// �ر�
// ����ֵ��
// ��
// ������
// 2011/6/15 ˧����
//////////////////////////////////////////////////////////////////////
void CWriteMSUI::closeEvent(QCloseEvent *event)
{
	event->ignore();
	CArg arg;
	arg.SetCode(0);
	NotifyObserver(&arg);
}
