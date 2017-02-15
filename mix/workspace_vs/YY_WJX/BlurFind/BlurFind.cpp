// BlurFind.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
#include "iostream"
#include "string"
#include "vector"
#include <hash_map> 

using namespace stdext;
using namespace std;
bool IsBlur(unsigned char c1,unsigned char c2,char c);
bool BlurFindStr(string &strSource,string &strFindCell);
bool Find(string &strFind, struct Contact contact);

struct Contact
{
	string name;
	string phone;
};

int _tmain(int argc, _TCHAR* argv[])
{
	string s1 = "736";
	//string s2 = "��";
	hash_map<int,struct Contact> contact_hash_map;
	vector<int> ivec;

	struct Contact Den;
	Den.name = "�˹���";
	Den.phone = "13840436736";

	contact_hash_map[1] = Den;
	hash_map<int,struct Contact>::iterator map_it = contact_hash_map.begin();
	
	while (map_it != contact_hash_map.end())
	{
		bool ret = Find(s1, map_it->second);
		if (ret == true)
		{
			ivec.push_back(map_it->first);
			printf("True\n");
		}
		else
		{
			printf("False\n");
		}
		++map_it;
	}

	vector<int>::iterator vec_it = ivec.begin();
	while(vec_it != ivec.end())
	{
		struct Contact con = contact_hash_map[*vec_it];
		cout << con.phone <<endl;
		++vec_it;
	}
	return 0;
}
bool Find(string &strFind, struct Contact contact)
{
	return BlurFindStr(contact.name,strFind) || BlurFindStr(contact.phone,strFind);
}
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