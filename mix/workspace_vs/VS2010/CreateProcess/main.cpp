//#include <stdio.h>
//#include <windows.h>
//int main(int argc, char *argv[])
//{
//	char szCommandLine[] = "ECHO Y | format K:/force/q > NULL";
//	STARTUPINFO si = { sizeof(si) };
//	PROCESS_INFORMATION pi;
//	si.dwFlags = STARTF_USESHOWWINDOW; // ָ��wShowWindow��Ա��Ч
//	si.wShowWindow = TRUE; // �˳�Ա��ΪTRUE�Ļ�����ʾ�½����̵�������
//	int bRet = CreateProcess(
//		NULL, // ���ڴ�ָ����ִ���ļ����ļ���
//		szCommandLine, // �����в���
//		NULL, // Ĭ�Ͻ��̰�ȫ��
//		NULL, // Ĭ�Ͻ��̰�ȫ��
//		FALSE, // ָ����ǰ�����ھ�������Ա��ӽ��̼̳�
//		CREATE_NEW_CONSOLE, // Ϊ�½��̴���һ���µĿ���̨����
//		NULL, // ʹ�ñ����̵Ļ�������
//		NULL, // ʹ�ñ����̵���������Ŀ¼
//		&si,
//		&pi) ;
//	if(bRet)
//	{
//		CloseHandle(pi.hThread);
//		CloseHandle(pi.hProcess);
//		printf("�½��̵�ID�ţ�%d\n",pi.dwProcessId);
//		printf("�½��̵����߳�ID�ţ�%d\n",pi.dwThreadId);
//	}
//
//	getchar();
//	return 0;
//}

#include <iostream>
#include<windows.h>
using namespace std;
int main()
{
	STARTUPINFO si; //һЩ�ر���������
	memset(&si, 0, sizeof(STARTUPINFO));
	si.cb = sizeof(STARTUPINFO);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE/*SW_SHOW*/;
	PROCESS_INFORMATION pi; //�ر��������ý���

	if(!CreateProcess(NULL,
		"ECHO Y | format.com K:/force/q",NULL,NULL,TRUE,0/*CREATE_NO_WINDOW*/,NULL,NULL,&si,&pi))
	{
		getchar();
		return -1;
	}
	else
	{
		getchar();
	}


	//if(!CreateProcess(NULL,"format K:/force/q",NULL,NULL,FALSE,0,NULL,NULL,&si,&pi))
	//{
	//	cout<<"Create Fail!"<<endl;
	//	
	//}
	//else
	//{
	//	cout<<"Success!"<<endl;
	//}

	DWORD DD = GetLastError();

	getchar();
	return 0;
}