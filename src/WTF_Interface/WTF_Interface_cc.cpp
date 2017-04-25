#include "WTF_Interface.h"

#include <map>
#include <string>

std::map<std::string,OPST_HANDLE_ARGS> g_currentArgs;

unsigned int __stdcall WTF_ArgsGet(SK_CERT_DESC_PROPERTY * pCertProperty, OPST_HANDLE_ARGS * args)
{
	OPST_HANDLE_ARGS tmpArgs = {0};

	for(std::map<std::string, OPST_HANDLE_ARGS>::iterator iter = g_currentArgs.begin(); iter != g_currentArgs.end(); iter++)  
	{  
		if (0 == strcmp(iter->first.c_str(), pCertProperty->szDeviceName))
		{
			tmpArgs = g_currentArgs[pCertProperty->szDeviceName];
			break;
		}
	}  

	memcpy(args, &tmpArgs, sizeof(OPST_HANDLE_ARGS));
	
	//{
	//	char bufferShow[1024] = {0};

	//	sprintf(bufferShow,"PID=%d --- %d %d %d %d", GetCurrentProcessId(), args->ghInst, args->hAPP, args->hCon, args->hDev);

	//	if (IDYES == MessageBoxA(NULL,bufferShow, "WTF_ArgsGet", MB_ICONEXCLAMATION))
	//	{

	//	}
	//	else
	//	{
	//		
	//	}
	//}


	return 0;
}

unsigned int __stdcall WTF_ArgsPut(SK_CERT_DESC_PROPERTY * pCertProperty, OPST_HANDLE_ARGS * args)
{
	OPST_HANDLE_ARGS tmpArgs = {0};

	memcpy(&tmpArgs,args, sizeof(OPST_HANDLE_ARGS));

	g_currentArgs[pCertProperty->szDeviceName] = tmpArgs;

	//{
	//	char bufferShow[1024] = {0};

	//	sprintf(bufferShow,"PID=%d --- %d %d %d %d", GetCurrentProcessId(), args->ghInst, args->hAPP, args->hCon, args->hDev);

	//	if (IDYES == MessageBoxA(NULL,bufferShow, "WTF_ArgsPut", MB_ICONEXCLAMATION))
	//	{

	//	}
	//	else
	//	{

	//	}
	//}

	return 0;
}

unsigned int __stdcall WTF_ArgsClr()
{
	g_currentArgs.clear();

	return 0;
}

std::map<std::string,HINSTANCE> g_currentInst;

HINSTANCE __stdcall WTF_LoadLibrary(char * pszDllPath)
{
	HINSTANCE ghInst = NULL;

	for(std::map<std::string, HINSTANCE>::iterator iter = g_currentInst.begin(); iter != g_currentInst.end(); iter++)  
	{  
		if (0 == strcmp(iter->first.c_str(), pszDllPath))
		{
			ghInst = g_currentInst[pszDllPath];
			break;
		}
	}  

	if (NULL == ghInst)
	{
		ghInst = LoadLibraryA(pszDllPath);
		g_currentInst[pszDllPath] = ghInst;
	}

	return ghInst;
}