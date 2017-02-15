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
	//ģ��ƥ�亯�����ж���ĸc�Ƿ�Ϊ���֣�c1c2������ĸ����һ�������������ֽڹ��ɣ���ÿ���ֽڵ����λ����ߵ�һλΪ1�� 

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
{//ģ��������֧���ú�������ĸ��ѯ,���� 
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
			//���Ǻ���,��Ҫ����ģ����ѯ 
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
		if(c&0x80)//���� 
		{ 
			i++; 
			while(j < nLenSource) 
			{ 
				char cs = strSource.at(j++).toAscii(); 
				k = j; 
				if(cs&0x80)//���� 
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
	else//��ĸ 
	{ 
		while(j < nLenSource) 
		{ 
			char cs = strSource.at(j++).toAscii(); 
			k = j; 
			if(cs&0x80)//���� 
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
