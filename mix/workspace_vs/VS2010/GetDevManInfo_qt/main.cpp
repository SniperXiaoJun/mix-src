#include <stdio.h>
#include <windows.h>
#include <setupapi.h>
#include <devguid.h>
#include <regstr.h>

#include <QString>

#pragma comment( lib,"Setupapi.lib")

int main(int argc, char *argv[])
{
	HDEVINFO hDevInfo;
	SP_DEVINFO_DATA DeviceInfoData;
	DWORD i;

	// Create a HDEVINFO with all present devices.
	hDevInfo = SetupDiGetClassDevs(
		NULL,
		0, // Enumerator
		0,
		DIGCF_PRESENT | DIGCF_ALLCLASSES
		);
	if( hDevInfo == INVALID_HANDLE_VALUE )
	{
		// Insert error handling here.
		return 1;
	}

	// Enumerate through all devices in Set.
	DeviceInfoData.cbSize = sizeof( SP_DEVINFO_DATA );
	for( i = 0;SetupDiEnumDeviceInfo( hDevInfo,i,&DeviceInfoData ); i++ )
	{
		DWORD DataT;
		LPTSTR buffer = NULL;
		DWORD buffersize = 0;
		// 
		// Call function with null to begin with, 
		// then use the returned buffer size 
		// to Alloc the buffer. Keep calling until
		// success or an unknown failure.
		// 
		while( !SetupDiGetDeviceRegistryProperty(
			hDevInfo,
			&DeviceInfoData,
			SPDRP_DEVICEDESC,//SPDRP_FRIENDLYNAME,
			&DataT,
			( PBYTE )buffer,
			buffersize,
			&buffersize ) )
		{
			if( GetLastError() == ERROR_INSUFFICIENT_BUFFER )
			{
				// Change the buffer size.
				if( buffer ) LocalFree( buffer );
				buffer =( LPTSTR )LocalAlloc( LPTR,buffersize );
			}
			else
			{
				// Insert error handling here.
				break;
			}
		}

		printf( "Result:[%s]\n",QString::fromUtf16(buffer).toLocal8Bit().data());
		if( buffer ) LocalFree( buffer );
	}

	if( GetLastError() != NO_ERROR && GetLastError() != ERROR_NO_MORE_ITEMS )
	{
		// Insert error handling here.
		return 1;
	}

	//  Cleanup
	SetupDiDestroyDeviceInfoList( hDevInfo );

	return 0;
}
