#include "WTF_Interface.h"

#include <map>
#include <string>

std::map<std::string,OPST_HANDLE_ARGS> g_currentArgs;

unsigned int __stdcall WTF_ArgsGet(SK_CERT_DESC_PROPERTY * pCertProperty, OPST_HANDLE_ARGS * args)
{
	OPST_HANDLE_ARGS tmpArgs = {0};

	tmpArgs = g_currentArgs[pCertProperty->szDeviceName];

	memcpy(args, &tmpArgs, sizeof(OPST_HANDLE_ARGS));

	return 0;
}

unsigned int __stdcall WTF_ArgsPut(SK_CERT_DESC_PROPERTY * pCertProperty, OPST_HANDLE_ARGS * args)
{
	OPST_HANDLE_ARGS tmpArgs = {0};

	memcpy(&tmpArgs,args, sizeof(OPST_HANDLE_ARGS));

	g_currentArgs[pCertProperty->szDeviceName] = tmpArgs;

	return 0;
}

unsigned int __stdcall WTF_ArgsClr()
{
	g_currentArgs.clear();

	return 0;
}