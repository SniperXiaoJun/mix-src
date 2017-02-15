#include "cres.h"
#include "windows.h"
#include "cstring"
#include "iostream"
using namespace std;

CRes::CRes(QWidget *parent, Qt::WFlags flags)
	: QMainWindow(parent, flags)
{
	ui.setupUi(this);
}

CRes::~CRes()
{

}


BOOL IsBlur(BYTE c1,BYTE c2,char c) 
{
	//模糊匹配函数，判断字母c是否为汉字（c1c2）的声母。（一个汉字由两个字节构成，且每个字节的最高位即左边第一位为1） 

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
	BOOL bMatch = FALSE; 
	while(nLeft <= nRight) 
	{ 
		i = (nLeft + nRight)/2; 
		if(nWordChinese > nWord[i][1]) 
		{
			nLeft = i+1; 
		}
		else if(nWordChinese < nWord[i][0]) 
		{
			nRight = i-1; 
		}
		else 
		{ 
			if(cEnd[i*5+4] == c) 
			bMatch = TRUE; 
			break; 
		} 
	} 
	return bMatch; 
} 



BOOL BlurFindStr(QString &strSource,QString &strFindCell) 
{//模糊搜索，支持用汉字用声母查询,返回 
	int nLenCell = strFindCell.count(); 
	int nLenSource = strSource.count(); 

	if(nLenCell < 1) 
	{
		return TRUE; 
	}
	if(nLenSource <1) 
	{
		return FALSE; 
	}

	strSource.toLower(); 
	strFindCell.toLower();


	BOOL bContainChar = FALSE; 
	int i,j,k; 
	for(i=0; i< nLenCell; i++) 
	{ 
		if( !(strFindCell.at(i).toAscii()&0x80) ) //1<<7 
		{
			//不是汉字,需要进行模糊查询 
			bContainChar = TRUE; 
			break; 
		} 
	} 
	j = 0; 
	int nMatchCharCount = 0; 
	BOOL bEqual = FALSE; 
	int ik; 
	for(i = 0; i< nLenCell && j < nLenSource; i++) 
	{ 
		ik = i; 
		char c = strFindCell.at(i).toAscii(); 
		if(c&0x80)//汉字 
		{ 
			i++; 
			while(j < nLenSource) 
			{ 
				char cs = strSource.at(j++).toAscii(); 
				k = j; 
				if(cs&0x80)//汉字 
				j++; 
				if(cs == c && 
				k < nLenSource && strSource.at(k).toAscii() == strFindCell.at(i).toAscii()) 
				{ 
					if(ik == 0) 
					bEqual = TRUE; 
					nMatchCharCount += 2; 
					break; 
				} 
				else if(i > 0) 
				{ 
					bEqual = FALSE; 
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
			char cs = strSource.at(j++).toAscii(); 
			k = j; 
			if(cs&0x80)//汉字 
			{ 
				j++; 
				if(IsBlur(cs,strSource.at(k).toAscii(),c)) 
				{ 
					if(ik == 0) 
						bEqual = TRUE; 
					nMatchCharCount++; 
					break; 
				} 
				else if(i > 0) 
				{ 
					bEqual = FALSE; 
					nMatchCharCount = 0; 
					i = 0; 
					break; 
				} 
				} 
				else if(cs == c) 
				{ 
					if(ik == 0) 
					bEqual = TRUE; 
					nMatchCharCount++; 
					break; 
				} 
				else if(i > 0) 
				{ 
					bEqual = FALSE; 
					nMatchCharCount = 0; 
					i = 0; 
					break; 
				} 
			} 
		} 
	} 
	if(bEqual && i == nLenCell && j == nLenSource) 
	{
		return TRUE+TRUE; 
	}
	else 
	{
		return (nMatchCharCount == nLenCell);
	}
}
