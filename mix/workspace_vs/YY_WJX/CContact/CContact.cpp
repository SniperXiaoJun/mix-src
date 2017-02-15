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
//	//模糊匹配函数，判断字母c是否为汉字（c1c2）的声母。（一个汉字由两个字节构成，且每个字节的最高位即左边第一位为1） 
//
//	//汉字声母区间表： 
//	static unsigned char cEnd[23*5+1] = "啊澳a芭怖b擦错c搭堕d蛾贰e发咐f噶过g哈紕h肌骏j喀阔k垃络l妈那m娜诺n哦沤o啪瀑p期群q然弱r撒所s塌唾t挖误w昔迅x压孕y匝座z"; 
//	static int nWord[23][2] = {0}; 
//	int i=0; 
//	if(nWord[0][0] == 0) 
//	{
//		//初始化nWord 
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
//{//模糊搜索，支持用汉字用声母查询,返回 
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
//			//不是汉字,需要进行模糊查询 
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
//		if(c&0x80)//汉字 
//		{ 
//			i++; 
//			while(j < nLenSource) 
//			{ 
//				char cs = strSource.at(j++).toAscii(); 
//				k = j; 
//				if(cs&0x80)//汉字 
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
//	else//字母 
//	{ 
//		while(j < nLenSource) 
//		{ 
//			char cs = strSource.at(j++).toAscii(); 
//			k = j; 
//			if(cs&0x80)//汉字 
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
{//模糊搜索，支持用汉字用声母查询,返回
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
		if( !(strFindCell[i]&0x80) ) //1<<7 //不是汉字,需要进行模糊查询
		{
			bContainChar = true; 
			break; 
		} 
	} 
	j = 0; 
	int nMatchCharCount = 0; 
	bool bEqual = false; //??什么作用？
	int ik; 
	for(i = 0; i< nLenCell && j < nLenSource; i++) 
	{ 
		ik = i; 
		char c = strFindCell[i]; 
		if(c&0x80)//汉字
		{ 
			i++; 
			while(j < nLenSource) 
			{ 
				char cs = strSource[j++]; 
				k = j; 
				if(cs&0x80)//汉字
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
		else//字母
		{ 
			while(j < nLenSource) 
			{ 
				char cs = strSource[j++]; 
				k = j; 
				if(cs&0x80)//汉字
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
{//模糊匹配函数，判断字母c是否为汉字（c1c2）的声母。（一个汉字由两个字节构成，且每个字节的最高位即左边第一位为1） 
	//汉字声母区间表：
	static unsigned char cEnd[23*5+1] = "啊澳a芭怖b擦错c搭堕d蛾贰e发咐f噶过g哈紕h肌骏j喀阔k垃络l妈那m娜诺n哦沤o啪瀑p期群q然弱r撒所s塌唾t挖误w昔迅x压孕y匝座z"; 
	static int nWord[23][2] = {0}; 
	int i=0; 
	if(nWord[0][0] == 0) 
	{
		//初始化nWord 
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