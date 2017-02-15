
//#include <windows.h>
//
//#include <stdio.h>
//
//#include <stdlib.h>
//
//void main(){
//
//	char strKey[]="SOFTWARE\\Microsoft\\Internet Explorer";
//
//	LPTSTR szSaveFileName;
//
//	HKEY key;
//
//	// 申请备份权限
//
//	HANDLE hToken;
//
//	TOKEN_PRIVILEGES tkp;
//
//	if(!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&hToken))
//	{
//		return;
//	}
//
//	LookupPrivilegeValue(NULL,SE_BACKUP_NAME,&tkp.Privileges[0].Luid);//申请SE_BACKUP_NAME权限
//
//	tkp.PrivilegeCount=1;
//
//	tkp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
//
//	AdjustTokenPrivileges(hToken,FALSE,&tkp,0,(PTOKEN_PRIVILEGES)NULL,0);
//
//	//开始备份工作
//
//	szSaveFileName=LPTSTR("D:\\KeyDate"); //注意文件不可存在否则无法成功
//
//	RegOpenKeyEx(
//
//		HKEY_CURRENT_USER,
//
//		(LPCTSTR)strKey,
//
//		0,
//
//		KEY_ALL_ACCESS,
//
//		&key);
//
//	RegSaveKey(key,szSaveFileName, NULL);
//
//	RegCloseKey(key);
//
//} 


// reg.cpp : Defines the entry point for the console application.
 
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "windows.h"
#include "malloc.h"

#include "RegOperation.h"
 
int main(int argc, char* argv[])
{  

	int va = system("set abcdpath=C:\\");

	return va;


	CRegOperation::Installation();

	DWORD word;

	int length;
	unsigned char * out = (unsigned char *)malloc(100);
	unsigned char * in = (unsigned char *)"change data";



	CRegOperation * ins = CRegOperation::Instance();

	ins->Init();

	ins->GetASymmetric(&word,1);

	ins->SetASymmetric(word+1,1);

	ins->GetASymmetric(&word,0);

	memset(out, 0, 100);
	ins->GetSelfCertWithLength(out,&length, 0);
	length = strlen((const char *)in);
	ins->SetSelfCertWithLength(in,length, 0);
	memset(out, 0, 100);
	ins->GetSelfCertWithLength(out,&length, 1);


	CRegOperation::Uninstall();

 //   DWORD dwIndex=0,NameSize,NameCnt,NameMaxLen,Type;
 //   DWORD KeySize,KeyCnt,KeyMaxLen,DateSize,MaxDateLen;
 //   HKEY hKey;
 //   char *szKeyName;
 //   char *szValueName;
 //   LPBYTE szValueDate;
 //   //打开关闭注册表---------------------------------------------------------------
 //   LPCTSTR SubKey="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
 //   if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,SubKey,0,KEY_ALL_ACCESS,&hKey)!=
 //       ERROR_SUCCESS)
 //   {
 //       printf("RegOpenKeyEx错误");
 //       return 0;
 //   }
 //   //获取子键信息---------------------------------------------------------------
 //   if(RegQueryInfoKey(hKey,NULL,NULL,NULL,&KeyCnt,&KeyMaxLen,NULL,&NameCnt,&NameMaxLen,&MaxDateLen,NULL,NULL)!=ERROR_SUCCESS)
 //   {
 //       printf("RegQueryInfoKey错误");
 //       ::RegCloseKey(hKey);
 //       return 0;
 //   }
 //   //枚举子键信息---------------------------------------------------------------
 //   for(dwIndex=0;dwIndex<KeyCnt;dwIndex++)        //枚举子键
 //   {
 //       KeySize=KeyMaxLen+1;            //因为RegQueryInfoKey得到的长度不包括0结束字符,所以应加1
 //       szKeyName=(char*)malloc(KeySize);
 //       RegEnumKeyEx(hKey,dwIndex,szKeyName,&KeySize,NULL,NULL,NULL,NULL);//枚举子键
 //       printf("%s\n",szKeyName);
 //   }
 //   //枚举键值信息---------------------------------------------------------------
 //   for(dwIndex=0;dwIndex<NameCnt;dwIndex++)    //枚举键值
 //   {
 //       DateSize=MaxDateLen+1;
 //       NameSize=NameMaxLen+1;
 //       szValueName=(char *)malloc(NameSize);
 //       szValueDate=(LPBYTE)malloc(DateSize);
 //       RegEnumValue(hKey,dwIndex,szValueName,&NameSize,NULL,&Type,szValueDate,&DateSize);//读取键值
 //        
 //       if(Type==REG_SZ)
 //       {
 //           ///*判断键值项类型并做其它操作......*/
 //           printf("%s\n",szValueName);
 //       }
 //       if(Type==REG_DWORD)
 //       {
 //            
 //       }      
 //   }
 //   RegCloseKey(hKey);
 //   //创建删除子键---------------------------------------------------------------
 //   if (ERROR_SUCCESS!=RegCreateKey(HKEY_LOCAL_MACHINE,"SOFTWARE\\Microsoft\\Windows\\MyKey",&hKey))
 //   {
 //       printf("创建子键失败!\n");
 //       return 0;
 //   }
 //   else
 //   {
 //       printf("创建子键成功!\n");
 //   }
 //   if(ERROR_SUCCESS==RegDeleteKey(HKEY_LOCAL_MACHINE,"SOFTWARE\\Microsoft\\Windows\\MyKey"))
 //   {
 //       printf("删除子键成功!\n");
 //   }
 //   else
 //   {
 //       printf("删除子键失败!\n");
 //       RegCloseKey(hKey);
 //       return 0;
 //   }
 //   RegCloseKey(hKey);
 //   //创建删除键值---------------------------------------------------------------
 //   if(RegOpenKeyEx(HKEY_LOCAL_MACHINE,SubKey,0,KEY_ALL_ACCESS,&hKey)!=ERROR_SUCCESS)
 //   {
 //       printf("创建HKEY失败!\n");
 //       return 0;
 //   }
 //   char *szValueName1="QQ";
 //   char *szValueDate1="This is QQ";
 //   UINT cbLen=strlen(szValueDate1);
 //   char *szValueName2="TT";
 //   UINT tmp=16;
 //   UINT *szValueDate2=&tmp;
 //   if(RegSetValueEx(hKey,szValueName1,0,REG_SZ,(const unsigned char *)szValueDate1,cbLen)==ERROR_SUCCESS)
 //   {
 //       printf("创建REG_SZ键值成功!\n");
 //   }
 //   else
 //   {
 //       printf("创建REG_SZ键值失败!\n");
 //       return 0;
 //   }
	//if(RegDeleteValue(hKey,szValueName1)==ERROR_SUCCESS)
 //   {
 //       printf("删除REG_SZ键值成功!\n");
 //   }
 //   else
 //   {
 //       printf("删除REG_SZ键值失败!\n");
 //       return 0;
	//}


 //   if(RegSetValueEx(hKey,szValueName2,0,REG_DWORD,(const unsigned char *)szValueDate2,4)==ERROR_SUCCESS)
 //   {
 //       printf("创建REG_DWORD键值成功!\n");
 //   }
 //   else
 //   {
 //       printf("创建REG_DWORD键值失败!\n");
 //       RegCloseKey(hKey);
 //       return 0;
 //   }

	//	if(RegDeleteValue(hKey,szValueName2)==ERROR_SUCCESS)
 //   {
 //       printf("删除REG_SZ键值成功!\n");
 //   }
 //   else
 //   {
 //       printf("删除REG_SZ键值失败!\n");
 //       return 0;
	//}
 //   RegCloseKey(hKey);
    return 0;
}