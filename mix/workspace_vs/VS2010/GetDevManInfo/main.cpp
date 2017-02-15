//
//#include <iostream>
//#include <windows.h>
//#include <iomanip>
//using namespace std;
//int main()
//{
//	SYSTEM_INFO systemInfo;
//	GetSystemInfo(&systemInfo);
//	cout <<"\t" << "处理器掩码: " << systemInfo.dwActiveProcessorMask << endl;
//	cout <<"\t" << "处理器个数: " << systemInfo.dwNumberOfProcessors << endl;
//	cout <<"\t" << "处理器分页大小: " << systemInfo.dwPageSize << endl;
//	cout <<"\t" << "处理器类型: " << systemInfo.dwProcessorType << endl;
//	cout <<"\t" << "最大寻址单元: " << systemInfo.lpMaximumApplicationAddress << endl;
//	cout <<"\t" << "最小寻址单元: " << systemInfo.lpMinimumApplicationAddress << endl;
//	cout <<"\t" << "处理器等级: " << systemInfo.wProcessorLevel << endl;
//	cout <<"\t" << "处理器版本: " << systemInfo.wProcessorRevision << endl;
//	return 0;
//}

//
//
//
//#include <stdio.h>
//#include <windows.h>
//#include <setupapi.h>
//#include <devguid.h>
//#include <regstr.h>
//
//#pragma comment( lib,"Setupapi.lib")
//
//int main(int argc, char* argv[])
//{
//	HDEVINFO hDevInfo;
//	SP_DEVINFO_DATA DeviceInfoData;
//	DWORD i;
//
//	// Create a HDEVINFO with all present devices.
//	hDevInfo = SetupDiGetClassDevs(
//		NULL,
//		0, // Enumerator
//		0,
//		DIGCF_PRESENT | DIGCF_ALLCLASSES
//		);
//	if( hDevInfo == INVALID_HANDLE_VALUE )
//	{
//		// Insert error handling here.
//		return 1;
//	}
//
//	// Enumerate through all devices in Set.
//	DeviceInfoData.cbSize = sizeof( SP_DEVINFO_DATA );
//	for( i = 0;SetupDiEnumDeviceInfo( hDevInfo,i,&DeviceInfoData ); i++ )
//	{
//		DWORD DataT;
//		LPTSTR buffer = NULL;
//		DWORD buffersize = 0;
//		// 
//		// Call function with null to begin with, 
//		// then use the returned buffer size 
//		// to Alloc the buffer. Keep calling until
//		// success or an unknown failure.
//		// 
//		while( !SetupDiGetDeviceRegistryProperty(
//			hDevInfo,
//			&DeviceInfoData,
//			SPDRP_DEVICEDESC,//SPDRP_FRIENDLYNAME,
//			&DataT,
//			( PBYTE )buffer,
//			buffersize,
//			&buffersize ) )
//		{
//			if( GetLastError() == ERROR_INSUFFICIENT_BUFFER )
//			{
//				// Change the buffer size.
//				if( buffer ) LocalFree( buffer );
//				buffer =( LPTSTR )LocalAlloc( LPTR,buffersize );
//			}
//			else
//			{
//				// Insert error handling here.
//				break;
//			}
//		}
//
//		printf( "Result:[%s]\n",buffer );
//		if( buffer ) LocalFree( buffer );
//	}
//
//	if( GetLastError() != NO_ERROR && GetLastError() != ERROR_NO_MORE_ITEMS )
//	{
//		// Insert error handling here.
//		return 1;
//	}
//
//	//  Cleanup
//	SetupDiDestroyDeviceInfoList( hDevInfo );
//
//	return 0;
//}

#include <stdio.h>

class a
{
public:
	virtual void fun()
	{
		printf("a");
	}
};

class b:public a
{
	virtual void fun()
	{
		printf("b");
	}
};

int main()
{
	a * aa = new b();

	aa->fun();

	aa = (a*)aa;


	aa->fun();
	return 0;
}