//#include "stdafx.h"
#include <windows.h> 
#include <stdio.h>

enum ENUM__AA
{

	E1,
	E2,
	
	
};


int main() 
{ 

	int DSLength = GetLogicalDriveStrings(0,NULL);

	//ͨ��GetLogicalDriveStrings()������ȡ�����������ַ�����Ϣ���ȡ�

	char* DStr = new char[DSLength];//�û�ȡ�ĳ����ڶ�������һ��c�����ַ�������

	GetLogicalDriveStrings(DSLength,(LPTSTR)DStr);

	//ͨ��GetLogicalDriveStrings���ַ�����Ϣ���Ƶ�����������,���б�������������������Ϣ��

	int DType;
	int si=0;


	for(int i=0;i<DSLength/4;++i)

		//Ϊ����ʾÿ����������״̬����ͨ��ѭ�����ʵ�֣�����DStr�ڲ������������A:\NULLB:\NULLC:\NULL����������Ϣ������DSLength/4���Ի�þ����ѭ����Χ

	{

		char dir[3]={DStr[si],':','\\'};

		//cout<<dir;


		DType = GetDriveType(DStr+i*4);

		//GetDriveType���������Ի�ȡ���������ͣ�����Ϊ�������ĸ�Ŀ¼

		if(DType == DRIVE_FIXED)

		{
			printf("%c",*dir); 

			printf("Ӳ��\n"); 

		}
		si+=4;


	}



	system("pause");//

	return 1;
}