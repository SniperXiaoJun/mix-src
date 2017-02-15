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

	//通过GetLogicalDriveStrings()函数获取所有驱动器字符串信息长度。

	char* DStr = new char[DSLength];//用获取的长度在堆区创建一个c风格的字符串数组

	GetLogicalDriveStrings(DSLength,(LPTSTR)DStr);

	//通过GetLogicalDriveStrings将字符串信息复制到堆区数组中,其中保存了所有驱动器的信息。

	int DType;
	int si=0;


	for(int i=0;i<DSLength/4;++i)

		//为了显示每个驱动器的状态，则通过循环输出实现，由于DStr内部保存的数据是A:\NULLB:\NULLC:\NULL，这样的信息，所以DSLength/4可以获得具体大循环范围

	{

		char dir[3]={DStr[si],':','\\'};

		//cout<<dir;


		DType = GetDriveType(DStr+i*4);

		//GetDriveType函数，可以获取驱动器类型，参数为驱动器的根目录

		if(DType == DRIVE_FIXED)

		{
			printf("%c",*dir); 

			printf("硬盘\n"); 

		}
		si+=4;


	}



	system("pause");//

	return 1;
}