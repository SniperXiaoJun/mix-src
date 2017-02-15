//获取系统信息
// 
//下面的实例实现了用vc5,得到一些系统信息(如有多少个驱动器，计算机名称)。

#include <Windows.h>
#include <stdio.h>
#include <string.h>


int main()
{
	SYSTEM_INFO SystemInfo = { 0 };
	::GetSystemInfo(&SystemInfo);

	//-------x-------

	MEMORYSTATUS MemoryStatus = { 0 };
	MemoryStatus.dwLength = sizeof(MEMORYSTATUS);
	::GlobalMemoryStatus(&MemoryStatus);

	//-------x-------

	char strComputerName[MAX_COMPUTERNAME_LENGTH+1];
	int len = MAX_COMPUTERNAME_LENGTH+1;
	::GetComputerNameA(strComputerName, (LPDWORD)&len);


	OSVERSIONINFOEX ifo;
	ifo.dwOSVersionInfoSize=sizeof(OSVERSIONINFOEX);
	GetVersionEx((OSVERSIONINFO *)&ifo);

	DWORD a=ifo.dwBuildNumber;
	DWORD b=ifo.dwMajorVersion;
	DWORD c=ifo.dwMinorVersion;
	DWORD d=ifo.dwOSVersionInfoSize;
	DWORD e=ifo.dwPlatformId;
	wchar_t * f=ifo.szCSDVersion;

	printf("%d,%d,%d,%d,%d,%s",a,b,c,d,e,f);

	return 0;
}