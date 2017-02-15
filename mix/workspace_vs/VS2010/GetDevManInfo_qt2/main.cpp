﻿#include <windows.h>   
#include <setupapi.h>   
#include <stdio.h>   
#include <devguid.h>   
#include <regstr.h>   
/* 函数声明 */  

#include <QString>

#pragma comment( lib,"Setupapi.lib")

/************************************* 
* BOOL EnumClassDevice( const GUID * InterfaceClassGuid ) 
* 功能    根据类型列举当前存在的设备 
* 参数    InterfaceClassGuid，所需列举设备接口类的GUID 
**************************************/  
BOOL EnumClassDevice( const GUID * InterfaceClassGuid )  

{  
	HDEVINFO DeviceInfoSet;  
	HDEVINFO NewDeviceInfoSet;  

	SP_DEVICE_INTERFACE_DATA DeviceInterfaceData;  
	PSP_DEVICE_INTERFACE_DETAIL_DATA lpDeviceInterfaceDetailData;  

	DWORD dwBufferSize = 0;  
	DWORD i;  
	// 创建空设备信息列表   
	DeviceInfoSet = SetupDiCreateDeviceInfoList(NULL, NULL);  

	if(DeviceInfoSet == INVALID_HANDLE_VALUE)   
	{  
		printf("CreateDeviceInfoList failed: %d\n", GetLastError());  
		return 0;  
	}  

	// 根据接口类型获得新的设备信息列表   

	NewDeviceInfoSet = SetupDiGetClassDevsEx(  
		InterfaceClassGuid,  
		NULL,  
		NULL,  
		DIGCF_PRESENT | DIGCF_DEVICEINTERFACE,  
		DeviceInfoSet,// 之前创建的设备信息列表   
		NULL,  
		NULL  
		);  
	if(NewDeviceInfoSet == INVALID_HANDLE_VALUE)  
	{  
		printf( "SetupDiGetClassDevsEx failed: %d\n", GetLastError() );  
		return 0;  
	}  
	// 设置 SP_DEVICE_INTERFACE_DATA 大小   
	DeviceInterfaceData.cbSize   
		= sizeof(SP_DEVICE_INTERFACE_DATA);  

	for (i=0; ;i++)  
	{  
		// 列举接口信息   
		BOOL bResult = SetupDiEnumDeviceInterfaces(  
			NewDeviceInfoSet,  
			NULL,  
			InterfaceClassGuid,  
			i,  
			&DeviceInterfaceData  
			);  
		if(!bResult)  
		{  
			if ( GetLastError()!=NO_ERROR &&  
				GetLastError()!=ERROR_NO_MORE_ITEMS )  
			{  
				printf("ERROR: (%d)",GetLastError());  
				return FALSE;  
			}  
			break;  
		}  
		else  
		{  
			// 为PSP_DEVICE_INTERFACE_DETAIL_DATA结构分配内存，填充   
			lpDeviceInterfaceDetailData = (PSP_DEVICE_INTERFACE_DETAIL_DATA)HeapAlloc(  
				GetProcessHeap(), 0,  
				sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA));  
			lpDeviceInterfaceDetailData->cbSize   
				= sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);  
			dwBufferSize = lpDeviceInterfaceDetailData->cbSize;  
			// 获得接口详细信息   
			while(!SetupDiGetDeviceInterfaceDetail(  
				NewDeviceInfoSet,  
				&DeviceInterfaceData,  
				lpDeviceInterfaceDetailData,  
				dwBufferSize,  
				&dwBufferSize,  
				NULL))  
			{  
				// 如果内存空间不足，再次分配，直到可以成功调用   
				if(ERROR_INSUFFICIENT_BUFFER==GetLastError())  
				{  
					lpDeviceInterfaceDetailData = (PSP_DEVICE_INTERFACE_DETAIL_DATA)HeapReAlloc(  
						GetProcessHeap(), 0,   
						lpDeviceInterfaceDetailData, dwBufferSize);  
					lpDeviceInterfaceDetailData->cbSize   
						= sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);  
				}                 
			}  
			// 显示信息   
			printf("DevicePath: %s\n",QString::fromUtf16(lpDeviceInterfaceDetailData->DevicePath).toLocal8Bit().data());  
			// lpDeviceInterfaceDetailData->DevicePath可作为CreateFile的参数，进行IO控制   

			// 释放内存   
			HeapFree(GetProcessHeap(),0,lpDeviceInterfaceDetailData);  
		}  
	}  
	SetupDiDestroyDeviceInfoList(DeviceInfoSet);  
	return TRUE;  
}  
/************************************* 
* BOOL EnumAllDevice( ) 
* 功能    列举当前存在的设备 
* 返回值   是否成功 
**************************************/  
BOOL EnumAllDevice()  
{  
	HDEVINFO hDevInfo;  
	SP_DEVINFO_DATA DeviceInfoData;  
	DWORD i;  

	printf("Displaying the Installed Devices\n\n");  

	// 得到所有设备 HDEVINFO    
	hDevInfo = SetupDiGetClassDevs(NULL,  
		0, // 无类型   
		0, // 无回调函数   
		DIGCF_PRESENT | DIGCF_ALLCLASSES );  
	if (hDevInfo == INVALID_HANDLE_VALUE)  
	{  
		return FALSE;  
	}  
	// 循环列举   
	DeviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);  
	for (i=0;SetupDiEnumDeviceInfo(hDevInfo,i,  
		&DeviceInfoData);i++)  
	{  
		DWORD DataT;  
		LPTSTR buffer = NULL;  
		DWORD buffersize = 0;  

		// 获取详细信息   
		while (!SetupDiGetDeviceRegistryProperty(  
			hDevInfo,  
			&DeviceInfoData,  
			SPDRP_DEVICEDESC,  
			&DataT,  
			(PBYTE)buffer,  
			buffersize,  
			&buffersize))  
		{  
			if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)  
			{  
				// 内存不足   
				if (buffer) HeapFree(GetProcessHeap(), 0, buffer);  
				buffer = (LPTSTR)HeapAlloc(GetProcessHeap(), 0,  buffersize);  
			}  
			else  
				break;  
		}  
		// 输出   
		printf("GUID:{%.8X-%.4X-%.4X--%.2X%.2X-%.2X%.2X%.2X%.2X%.2X%.2X} "  
			"Device: %s\n",  
			DeviceInfoData.ClassGuid.Data1,  
			DeviceInfoData.ClassGuid.Data2,  
			DeviceInfoData.ClassGuid.Data3,  
			DeviceInfoData.ClassGuid.Data4[0],  
			DeviceInfoData.ClassGuid.Data4[1],  
			DeviceInfoData.ClassGuid.Data4[2],  
			DeviceInfoData.ClassGuid.Data4[3],  
			DeviceInfoData.ClassGuid.Data4[4],  
			DeviceInfoData.ClassGuid.Data4[5],  
			DeviceInfoData.ClassGuid.Data4[6],  
			DeviceInfoData.ClassGuid.Data4[7],QString::fromUtf16(buffer).toLocal8Bit().data());  

		if (buffer) HeapFree(GetProcessHeap(), 0, buffer);  
	}  

	if ( GetLastError()!=NO_ERROR &&  
		GetLastError()!=ERROR_NO_MORE_ITEMS )  
	{  
		return FALSE;  
	}  
	//  释放   
	SetupDiDestroyDeviceInfoList(hDevInfo);  
	return TRUE;  
}  

int main( int argc, char *argv[ ], char *envp[ ] )  
{  
	// 列举所有设备   
	printf("Enumerating All Device\n\n");  
	EnumAllDevice();  
	// 列举磁盘分卷驱动器设备   
	printf("\n\nEnumerating Present Volume \n\n");  
	EnumClassDevice(&GUID_DEVINTERFACE_VOLUME);  
	return 0;  
}  