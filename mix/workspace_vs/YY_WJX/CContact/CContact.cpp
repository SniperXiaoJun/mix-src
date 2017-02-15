#include "CContact.h"

typedef unsigned char BYTE;
typedef int BOOL;

//BOOL IsBlur(BYTE c1,BYTE c2,char c);
//BOOL BlurFindStr(QString &strSource,QString &strFindCell);

#include <string>
using namespace std;
bool IsBlur(unsigned char c1,unsigned char c2,char c);
bool BlurFindStr(string &strSource,string &strFindCell);


CContact::CContact(QWidget *parent, Qt::WFlags flags)
	: QMainWindow(parent, flags)
{
	ui.setupUi(this);

	connect(ui.lineEdit, SIGNAL(textChanged(const QString &)), this, SLOT(SlotFind(const QString &)));
}

CContact::~CContact()
{

}

void CContact::SlotFind(const QString str)
{
	if(0 == str.count())
	{
		for(int i = 0; i < ui.listWidget->count(); i++)
		{
			ui.listWidget->item(i)->setHidden(false);
		}
	}
	else
	{
		for(int i = 0; i < ui.listWidget->count(); i++)
		{
			QString strSrc(ui.listWidget->item(i)->text());
			QString strSub = str;

			strSrc = strSrc.toLocal8Bit();
			strSub = strSub.toLocal8Bit();

			if(BlurFindStr(strSrc.toStdString(),strSub.toStdString()))
			{
				ui.listWidget->item(i)->setHidden(false);
			}
			else
			{
				ui.listWidget->item(i)->setHidden(true);
			}
		}
	}
}
//
//BOOL IsBlur(BYTE c1,BYTE c2,char c) 
//{
//	//ģ��ƥ�亯�����ж���ĸc�Ƿ�Ϊ���֣�c1c2������ĸ����һ�������������ֽڹ��ɣ���ÿ���ֽڵ����λ����ߵ�һλΪ1�� 
//
//	//������ĸ����� 
//	static unsigned char cEnd[23*5+1] = "����a�Ų�b����c���d�귡e����f����g����h����j����k����l����m��ŵnŶŽož��p��ȺqȻ��r����s����t����w��Ѹxѹ��y����z"; 
//	static int nWord[23][2] = {0}; 
//	int i=0; 
//	if(nWord[0][0] == 0) 
//	{
//		//��ʼ��nWord 
//		for(i = 0;i < 23; i++) 
//		{ 
//		nWord[i][0] = cEnd[i*5]*256 + cEnd[i*5+1]; 
//		nWord[i][1] = cEnd[i*5+2]*256 + cEnd[i*5+3]; 
//		} 
//	} 
//	int nWordChinese = c1 * 256 + c2; 
//	int nLeft = 0,nRight = 22; 
//	BOOL bMatch = FALSE; 
//	while(nLeft <= nRight) 
//	{ 
//		i = (nLeft + nRight)/2; 
//		if(nWordChinese > nWord[i][1]) 
//		{
//			nLeft = i+1; 
//		}
//		else if(nWordChinese < nWord[i][0]) 
//		{
//			nRight = i-1; 
//		}
//		else 
//		{ 
//			if(cEnd[i*5+4] == c) 
//			bMatch = TRUE; 
//			break; 
//		} 
//	} 
//	return bMatch; 
//} 
//
//
//
//BOOL BlurFindStr(QString &strSource,QString &strFindCell) 
//{//ģ��������֧���ú�������ĸ��ѯ,���� 
//
//	
//	if(strSource.contains (strFindCell, Qt::CaseInsensitive))
//	{
//		return TRUE;
//	}
//
//	int nLenCell = strFindCell.count(); 
//	int nLenSource = strSource.count(); 
//
//	if(nLenCell < 1) 
//	{
//		return TRUE; 
//	}
//	if(nLenSource <1) 
//	{
//		return FALSE; 
//	}
//
//	//strSource = strSource.toLower(); 
//	//strFindCell = strFindCell.toLower();
//
//
//	BOOL bContainChar = FALSE; 
//	int i,j,k; 
//	for(i=0; i< nLenCell; i++) 
//	{ 
//		if( !(strFindCell.at(i).toAscii()&0x80) ) //1<<7 
//		{
//			//���Ǻ���,��Ҫ����ģ����ѯ 
//			bContainChar = TRUE; 
//			break; 
//		} 
//	} 
//	j = 0; 
//	int nMatchCharCount = 0; 
//	BOOL bEqual = FALSE; 
//	int ik; 
//	for(i = 0; i< nLenCell && j < nLenSource; i++) 
//	{ 
//		ik = i; 
//		char c = strFindCell.at(i).toAscii(); 
//		if(c&0x80)//���� 
//		{ 
//			i++; 
//			while(j < nLenSource) 
//			{ 
//				char cs = strSource.at(j++).toAscii(); 
//				k = j; 
//				if(cs&0x80)//���� 
//				j++; 
//				if(cs == c && 
//				k < nLenSource && strSource.at(k).toAscii() == strFindCell.at(i).toAscii()) 
//				{ 
//					if(ik == 0) 
//					bEqual = TRUE; 
//					nMatchCharCount += 2; 
//					break; 
//				} 
//				else if(i > 0) 
//				{ 
//					bEqual = FALSE; 
//					nMatchCharCount = 0; 
//					i = 0; 
//					break; 
//				} 
//			} 
//		} 
//	else//��ĸ 
//	{ 
//		while(j < nLenSource) 
//		{ 
//			char cs = strSource.at(j++).toAscii(); 
//			k = j; 
//			if(cs&0x80)//���� 
//			{ 
//				j++; 
//				if(IsBlur(cs,strSource.at(k).toAscii(),c)) 
//				{ 
//					if(ik == 0) 
//						bEqual = TRUE; 
//					nMatchCharCount++; 
//					break; 
//				} 
//				else if(i > 0) 
//				{ 
//					bEqual = FALSE; 
//					nMatchCharCount = 0; 
//					i = 0; 
//					break; 
//				} 
//				} 
//				else if(cs == c) 
//				{ 
//					if(ik == 0) 
//					bEqual = TRUE; 
//					nMatchCharCount++; 
//					break; 
//				} 
//				else if(i > 0) 
//				{ 
//					bEqual = FALSE; 
//					nMatchCharCount = 0; 
//					i = 0; 
//					break; 
//				} 
//			} 
//		} 
//	} 
//	if(bEqual && i == nLenCell && j == nLenSource) 
//	{
//		return TRUE+TRUE; 
//	}
//	else 
//	{
//		return (nMatchCharCount == nLenCell);
//	}
//}


























bool BlurFindStr(string &strSource,string &strFindCell)
{//ģ��������֧���ú�������ĸ��ѯ,����
	int nLenCell = strFindCell.size();
	int nLenSource = strSource.size(); 
	if(nLenCell < 1) 
		return true; 
	if(nLenSource <1) 
		return false; 
	//strSource.MakeLower(); 
	//strFindCell.MakeLower(); 
	for (int i = 0; i < nLenCell; i++)
	{
		strFindCell[i] = tolower(strFindCell[i]);
	}
	for (int i = 0; i < nLenSource; i++)
	{
		strSource[i] = tolower(strSource[i]);
	}

	bool bContainChar = false; 
	int i,j,k; 

	for(i=0; i< nLenCell; i++) 
	{ 
		if( !(strFindCell[i]&0x80) ) //1<<7 //���Ǻ���,��Ҫ����ģ����ѯ
		{
			bContainChar = true; 
			break; 
		} 
	} 
	j = 0; 
	int nMatchCharCount = 0; 
	bool bEqual = false; //??ʲô���ã�
	int ik; 
	for(i = 0; i< nLenCell && j < nLenSource; i++) 
	{ 
		ik = i; 
		char c = strFindCell[i]; 
		if(c&0x80)//����
		{ 
			i++; 
			while(j < nLenSource) 
			{ 
				char cs = strSource[j++]; 
				k = j; 
				if(cs&0x80)//����
					j++; 
				if(cs == c && k < nLenSource && strSource[k] == strFindCell[i]) 
				{ 
					if(ik == 0) 
						bEqual = true; 
					nMatchCharCount += 2; 
					break; 
				} 
				else if(i > 0) 
				{ 
					bEqual = false; 
 					nMatchCharCount = 0; 
					i = 0; 
					break; 
				} 
			} 
		} 
		else//��ĸ
		{ 
			while(j < nLenSource) 
			{ 
				char cs = strSource[j++]; 
				k = j; 
				if(cs&0x80)//����
				{ 
					j++; 
					if(IsBlur(cs,strSource[k],c)) 
					{ 
						if(ik == 0) 
							bEqual = true; 
						nMatchCharCount++; 
						break; 
					} 
					else if(i > 0) 
					{ 
						bEqual = false; 
						nMatchCharCount = 0; 
						i = 0; 
						break; 
					} 
				} 
				else if(cs == c) 
				{ 
					if(ik == 0) 
						bEqual = false; 
					nMatchCharCount++; 
					break; 
				} 
				else if(i > 0) 
				{ 
					bEqual = false; 
					nMatchCharCount = 0; 
					i = 0; 
					break; 
				} 
			}
		}
	} 
	if(bEqual && i == nLenCell && j == nLenSource) 
		return true; 
	else 
		return (nMatchCharCount == nLenCell);

}
bool IsBlur(unsigned char c1,unsigned char c2,char c)
{//ģ��ƥ�亯�����ж���ĸc�Ƿ�Ϊ���֣�c1c2������ĸ����һ�������������ֽڹ��ɣ���ÿ���ֽڵ����λ����ߵ�һλΪ1�� 
	//������ĸ�����
	static unsigned char cEnd[23*5+1] = "����a�Ų�b����c���d�귡e����f����g����h����j����k����l����m��ŵnŶŽož��p��ȺqȻ��r����s����t����w��Ѹxѹ��y����z"; 
	static int nWord[23][2] = {0}; 
	int i=0; 
	if(nWord[0][0] == 0) 
	{
		//��ʼ��nWord 
		for(i = 0;i < 23; i++) 
		{ 
			nWord[i][0] = cEnd[i*5]*256 + cEnd[i*5+1]; 
			nWord[i][1] = cEnd[i*5+2]*256 + cEnd[i*5+3]; 
		} 
	} 
	int nWordChinese = c1 * 256 + c2; 
	int nLeft = 0,nRight = 22; 
	bool bMatch = false; 
	while(nLeft <= nRight) 
	{ 
		i = (nLeft + nRight)/2; 
		if(nWordChinese > nWord[i][1]) 
			nLeft = i+1; 
		else if(nWordChinese < nWord[i][0]) 
			nRight = i-1; 
		else 
		{ 
			if(cEnd[i*5+4] == c) 
				bMatch = true; 
			break; 
		} 
	}
	return 
		bMatch; 
}