
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
//	// ���뱸��Ȩ��
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
//	LookupPrivilegeValue(NULL,SE_BACKUP_NAME,&tkp.Privileges[0].Luid);//����SE_BACKUP_NAMEȨ��
//
//	tkp.PrivilegeCount=1;
//
//	tkp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
//
//	AdjustTokenPrivileges(hToken,FALSE,&tkp,0,(PTOKEN_PRIVILEGES)NULL,0);
//
//	//��ʼ���ݹ���
//
//	szSaveFileName=LPTSTR("D:\\KeyDate"); //ע���ļ����ɴ��ڷ����޷��ɹ�
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
 //   //�򿪹ر�ע���---------------------------------------------------------------
 //   LPCTSTR SubKey="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
 //   if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,SubKey,0,KEY_ALL_ACCESS,&hKey)!=
 //       ERROR_SUCCESS)
 //   {
 //       printf("RegOpenKeyEx����");
 //       return 0;
 //   }
 //   //��ȡ�Ӽ���Ϣ---------------------------------------------------------------
 //   if(RegQueryInfoKey(hKey,NULL,NULL,NULL,&KeyCnt,&KeyMaxLen,NULL,&NameCnt,&NameMaxLen,&MaxDateLen,NULL,NULL)!=ERROR_SUCCESS)
 //   {
 //       printf("RegQueryInfoKey����");
 //       ::RegCloseKey(hKey);
 //       return 0;
 //   }
 //   //ö���Ӽ���Ϣ---------------------------------------------------------------
 //   for(dwIndex=0;dwIndex<KeyCnt;dwIndex++)        //ö���Ӽ�
 //   {
 //       KeySize=KeyMaxLen+1;            //��ΪRegQueryInfoKey�õ��ĳ��Ȳ�����0�����ַ�,����Ӧ��1
 //       szKeyName=(char*)malloc(KeySize);
 //       RegEnumKeyEx(hKey,dwIndex,szKeyName,&KeySize,NULL,NULL,NULL,NULL);//ö���Ӽ�
 //       printf("%s\n",szKeyName);
 //   }
 //   //ö�ټ�ֵ��Ϣ---------------------------------------------------------------
 //   for(dwIndex=0;dwIndex<NameCnt;dwIndex++)    //ö�ټ�ֵ
 //   {
 //       DateSize=MaxDateLen+1;
 //       NameSize=NameMaxLen+1;
 //       szValueName=(char *)malloc(NameSize);
 //       szValueDate=(LPBYTE)malloc(DateSize);
 //       RegEnumValue(hKey,dwIndex,szValueName,&NameSize,NULL,&Type,szValueDate,&DateSize);//��ȡ��ֵ
 //        
 //       if(Type==REG_SZ)
 //       {
 //           ///*�жϼ�ֵ�����Ͳ�����������......*/
 //           printf("%s\n",szValueName);
 //       }
 //       if(Type==REG_DWORD)
 //       {
 //            
 //       }      
 //   }
 //   RegCloseKey(hKey);
 //   //����ɾ���Ӽ�---------------------------------------------------------------
 //   if (ERROR_SUCCESS!=RegCreateKey(HKEY_LOCAL_MACHINE,"SOFTWARE\\Microsoft\\Windows\\MyKey",&hKey))
 //   {
 //       printf("�����Ӽ�ʧ��!\n");
 //       return 0;
 //   }
 //   else
 //   {
 //       printf("�����Ӽ��ɹ�!\n");
 //   }
 //   if(ERROR_SUCCESS==RegDeleteKey(HKEY_LOCAL_MACHINE,"SOFTWARE\\Microsoft\\Windows\\MyKey"))
 //   {
 //       printf("ɾ���Ӽ��ɹ�!\n");
 //   }
 //   else
 //   {
 //       printf("ɾ���Ӽ�ʧ��!\n");
 //       RegCloseKey(hKey);
 //       return 0;
 //   }
 //   RegCloseKey(hKey);
 //   //����ɾ����ֵ---------------------------------------------------------------
 //   if(RegOpenKeyEx(HKEY_LOCAL_MACHINE,SubKey,0,KEY_ALL_ACCESS,&hKey)!=ERROR_SUCCESS)
 //   {
 //       printf("����HKEYʧ��!\n");
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
 //       printf("����REG_SZ��ֵ�ɹ�!\n");
 //   }
 //   else
 //   {
 //       printf("����REG_SZ��ֵʧ��!\n");
 //       return 0;
 //   }
	//if(RegDeleteValue(hKey,szValueName1)==ERROR_SUCCESS)
 //   {
 //       printf("ɾ��REG_SZ��ֵ�ɹ�!\n");
 //   }
 //   else
 //   {
 //       printf("ɾ��REG_SZ��ֵʧ��!\n");
 //       return 0;
	//}


 //   if(RegSetValueEx(hKey,szValueName2,0,REG_DWORD,(const unsigned char *)szValueDate2,4)==ERROR_SUCCESS)
 //   {
 //       printf("����REG_DWORD��ֵ�ɹ�!\n");
 //   }
 //   else
 //   {
 //       printf("����REG_DWORD��ֵʧ��!\n");
 //       RegCloseKey(hKey);
 //       return 0;
 //   }

	//	if(RegDeleteValue(hKey,szValueName2)==ERROR_SUCCESS)
 //   {
 //       printf("ɾ��REG_SZ��ֵ�ɹ�!\n");
 //   }
 //   else
 //   {
 //       printf("ɾ��REG_SZ��ֵʧ��!\n");
 //       return 0;
	//}
 //   RegCloseKey(hKey);
    return 0;
}