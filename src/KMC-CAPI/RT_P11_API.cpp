#include "RT_P11_API.h"
#include "FILE_LOG.h"
#include "o_all_type_def.h"
#include "o_all_func_def.h"
#include <string.h>
#include <pkcs11/cryptoki-win32.h>
#include <Windows.h>

#define GM_ECC_512_BYTES_LEN (32*2)

CK_BBOOL bTrue = CK_TRUE;
CK_BBOOL bFalse = CK_FALSE;

HMODULE g_hP11Module = NULL;
CK_FUNCTION_LIST* g_FunctionPtr = NULL;


CK_ULONG IN_LoadLibrary( void )
{
	CK_RV rv; 	// Return Code 
	char *perror;	
	CK_RV (*symPtr)(CK_FUNCTION_LIST_PTR_PTR);

	perror = 0;

	//Load library.
	if(g_hP11Module == NULL)
	{
		g_hP11Module = LoadLibraryA("TFTknP11.dll"); 
		if (!g_hP11Module)
		{
			return CKR_GENERAL_ERROR;   
		}

		//Load C_GetFunctionList.
		symPtr = (CK_RV (*)(CK_FUNCTION_LIST_PTR_PTR))GetProcAddress(g_hP11Module, "C_GetFunctionList");  
		if (!symPtr)
		{
			return CKR_GENERAL_ERROR;  
		}

		rv = symPtr(&g_FunctionPtr); 
		if(rv != CKR_OK)
			return rv;

		rv = g_FunctionPtr->C_Initialize(NULL);
		if(rv != CKR_OK)
			return rv;
	}

	return CKR_OK;
}


void IN_FreeLibrary()
{
	if(g_hP11Module != NULL)
	{
		g_FunctionPtr->C_Finalize(NULL);
		FreeLibrary(g_hP11Module);
		g_hP11Module=NULL;
		g_FunctionPtr=NULL;
	}
}

int RT_P11_API_SetMetas(
	unsigned char *pAuthKey, int uiAuthKeyLen,
	char *pSecID, int uiSecIDLen,
	unsigned char *pHMac, int uiHMacLen,
	char * pszPIN, unsigned int * pulRetry
	)
{
	CK_RV rv = CKR_OK;

	CK_ULONG ulSlotID = 0;
	CK_ULONG ulAuthSlotID = 0;
	CK_SLOT_ID szSlotID[256];
	CK_ULONG ulSlotCount = 256;
	int i = 0;
	CK_SESSION_HANDLE hSession = NULL_PTR;

	IN_LoadLibrary();

	ulSlotCount = sizeof(szSlotID)/sizeof(CK_SLOT_ID);
	rv = g_FunctionPtr->C_GetSlotList(bTrue, szSlotID, &ulSlotCount);
	if(rv != CKR_OK)
	{
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
		goto err;
	}

	FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);

	ulAuthSlotID = atoi((char *) pAuthKey);

	for(i = 0; i < ulSlotCount; i++)
	{
		if (szSlotID[i] == ulAuthSlotID)
		{
			continue;
		}
		else
		{
			ulSlotID = szSlotID[i];
			break;
		}
	}

	rv = g_FunctionPtr->C_OpenSession(ulSlotID, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession);
	if (rv != CKR_OK) {
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
		goto err;
	}

	rv = g_FunctionPtr->C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR)pszPIN, strlen(pszPIN));
	if (rv!=CKR_OK && rv!=CKR_USER_ALREADY_LOGGED_IN) {
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
		goto err;
	}

	{{
		// this add secid
		CK_KEY_TYPE		keyType = CKK_GENERIC_SECRET;
		CK_OBJECT_CLASS dataClass = CKO_DATA;
		CK_OBJECT_HANDLE hSecID=NULL_PTR;
		CK_OBJECT_HANDLE hObjectFind[16] = {0};
		CK_ULONG ulObjectFind = 16;

		CK_ATTRIBUTE secIDCreateTemplate[] = {
			{CKA_CLASS, &dataClass, sizeof(dataClass)},
			{CKA_TOKEN, &bTrue, sizeof(bTrue)},
			{CKA_OBJECT_ID, RT_SECID, strlen(RT_SECID)}, // 数据对象 CKA_OBJECT_ID
			{CKA_VALUE, pSecID, uiSecIDLen}
		};

		CK_ATTRIBUTE findTemplate[] = {
			{CKA_CLASS, &dataClass, sizeof(dataClass)},
			{CKA_ID, RT_SECID, strlen(RT_SECID)}
		};


		rv = g_FunctionPtr->C_FindObjectsInit(hSession, findTemplate, sizeof(findTemplate)/sizeof(CK_ATTRIBUTE));
		if (rv != CKR_OK) {
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
			goto err;
		}

		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);

		rv = g_FunctionPtr->C_FindObjects(hSession, hObjectFind, sizeof(hObjectFind)/sizeof(CK_OBJECT_HANDLE), &ulObjectFind); 
		g_FunctionPtr->C_FindObjectsFinal(hSession);
		if (rv != CKR_OK) {
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
			goto err;
		}
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);

		if(ulObjectFind > 0)
		{
			
		}
		else
		{
			FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
			FILE_LOG_HEX(file_log_name, (unsigned char *)pSecID, strlen(pSecID));

			rv = g_FunctionPtr->C_CreateObject(hSession, secIDCreateTemplate, sizeof(secIDCreateTemplate) / sizeof(CK_ATTRIBUTE), &hSecID);
			if (rv != CKR_OK) {
				FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
				goto err;
			}
			
		}

		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, ulObjectFind);
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
	}}


	{{
		// HMAC密钥
		// 每个用户有9个HMAC密钥，每个密钥长度为32字节
		// 09 +
		// 0120 3131313131313131313131313131313131313131313131313131313131313131 +
		// 0220 3232323232323232323232323232323232323232323232323232323232323232 +
		// 0320 3333333333333333333333333333333333333333333333333333333333333333 +
		// 0420 3434343434343434343434343434343434343434343434343434343434343434 +
		// 0520 3535353535353535353535353535353535353535353535353535353535353535 +
		// 0620 3636363636363636363636363636363636363636363636363636363636363636 +
		// 0720 3737373737373737373737373737373737373737373737373737373737373737 + 
		// 0820 3838383838383838383838383838383838383838383838383838383838383838 + 09 3939393939393939393939393939393939393939393939393939393939393939

		// A类用户
		// char *pszHMACKey = "03012031313131313131313131313131313131313131313131313131313131313131310520353535353535353535353535353535353535353535353535353535353535353506203636363636363636363636363636363636363636363636363636363636363636";
		unsigned char bHMACKey[512];

		CK_KEY_TYPE		keyType = CKK_GENERIC_SECRET;
		CK_OBJECT_CLASS SecretClass = CKO_SECRET_KEY;
		CK_ATTRIBUTE KPXTemplate[] = {
			{CKA_CLASS, &SecretClass, sizeof(SecretClass)},
			{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
			{CKA_TOKEN, &bTrue, sizeof(bTrue)},
			{CKA_ID, RT_HMAC_KEY, strlen(RT_HMAC_KEY)},
			{CKA_ENCRYPT, &bTrue, sizeof(bTrue)},
			{CKA_VALUE, (unsigned char *)bHMACKey, 1+1+32+1+32+32}
		};
		CK_OBJECT_HANDLE hKPX=NULL_PTR;
		int pos = 0;
		CK_OBJECT_HANDLE hObjectFind[16] = {0};
		CK_ULONG ulObjectFind = 16;


		CK_ATTRIBUTE findTemplate[] = {
			{CKA_CLASS, &SecretClass, sizeof(SecretClass)},
			{CKA_ID, RT_SECID, strlen(RT_SECID)}
		};

		rv = g_FunctionPtr->C_FindObjectsInit(hSession, findTemplate, sizeof(findTemplate)/sizeof(CK_ATTRIBUTE));
		if (rv != CKR_OK) {
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
			goto err;
		}

		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);

		rv = g_FunctionPtr->C_FindObjects(hSession, hObjectFind, sizeof(hObjectFind)/sizeof(CK_OBJECT_HANDLE), &ulObjectFind); 
		g_FunctionPtr->C_FindObjectsFinal(hSession);
		if (rv != CKR_OK) {
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
			goto err;
		}
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);

		if(ulObjectFind > 0)
		{

		}
		else
		{
			switch(pSecID[0])
			{
			case '1':
				//A类用户CKA_VALUE：
				//	03 + {01+20+HK1} + {05+20+HK5} + {06+20+HK6}
				pos = 0;
				bHMACKey[pos] = 0x03;
				pos+=1;
				bHMACKey[pos] = 0x01;
				pos+=1;
				bHMACKey[pos] = 0x20;
				pos+=1;
				memcpy(bHMACKey+pos,pHMac+(0x01-1)*32,32);
				pos+=32;
				bHMACKey[pos] = 0x05;
				pos+=1;
				bHMACKey[pos] = 0x20;
				pos+=1;
				memcpy(bHMACKey+pos,pHMac+(0x05-1)*32,32);
				pos+=32;
				bHMACKey[pos] = 0x06;
				pos+=1;
				bHMACKey[pos] = 0x20;
				pos+=1;
				memcpy(bHMACKey+pos,pHMac+(0x06-1)*32,32);
				pos+=32;
				KPXTemplate[5].ulValueLen = pos;
				break;
			case '2':
				//B0类用户CKA_VALUE：
				//	04 + {02+20+HK2} + {06+20+HK6} + {07+20+HK7} + {08+20+HK8}
				pos = 0;
				bHMACKey[pos] = 0x04;
				pos+=1;
				bHMACKey[pos] = 0x02;
				pos+=1;
				bHMACKey[pos] = 0x20;
				pos+=1;
				memcpy(bHMACKey+pos,pHMac+(0x02-1)*32,32);
				pos+=32;
				bHMACKey[pos] = 0x06;
				pos+=1;
				bHMACKey[pos] = 0x20;
				pos+=1;
				memcpy(bHMACKey+pos,pHMac+(0x06-1)*32,32);
				pos+=32;
				bHMACKey[pos] = 0x07;
				pos+=1;
				bHMACKey[pos] = 0x20;
				pos+=1;
				memcpy(bHMACKey+pos,pHMac+(0x07-1)*32,32);
				pos+=32;
				bHMACKey[pos] = 0x08;
				pos+=1;
				bHMACKey[pos] = 0x20;
				pos+=1;
				memcpy(bHMACKey+pos,pHMac+(0x08-1)*32,32);
				pos+=32;
				KPXTemplate[5].ulValueLen = pos;
				break;
			case '3':
				//B1类用户CKA_VALUE：
				//	02 + {03+20+HK3} + {08+20+HK8}
				pos = 0;
				bHMACKey[pos] = 0x02;
				pos+=1;
				bHMACKey[pos] = 0x03;
				pos+=1;
				bHMACKey[pos] = 0x20;
				pos+=1;
				memcpy(bHMACKey+pos,pHMac+(0x03-1)*32,32);
				pos+=32;
				bHMACKey[pos] = 0x08;
				pos+=1;
				bHMACKey[pos] = 0x20;
				pos+=1;
				memcpy(bHMACKey+pos,pHMac+(0x08-1)*32,32);
				pos+=32;
				KPXTemplate[5].ulValueLen = pos;
				break;
			case '4':
				//C类用户CKA_VALUE：
				//	03 + {04+20+HK4} + {08+20+HK8} + {09+20+HK9}
				pos = 0;
				bHMACKey[pos] = 0x03;
				pos+=1;
				bHMACKey[pos] = 0x04;
				pos+=1;
				bHMACKey[pos] = 0x20;
				pos+=1;
				memcpy(bHMACKey+pos,pHMac+(0x04-1)*32,32);
				pos+=32;
				bHMACKey[pos] = 0x08;
				pos+=1;
				bHMACKey[pos] = 0x20;
				pos+=1;
				memcpy(bHMACKey+pos,pHMac+(0x08-1)*32,32);
				pos+=32;
				bHMACKey[pos] = 0x09;
				pos+=1;
				bHMACKey[pos] = 0x20;
				pos+=1;
				memcpy(bHMACKey+pos,pHMac+(0x09-1)*32,32);
				pos+=32;
				KPXTemplate[5].ulValueLen = pos;
				break;
			default:
				break;
			}

			FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
			FILE_LOG_HEX(file_log_name, bHMACKey, pos);

			rv = g_FunctionPtr->C_CreateObject(hSession, KPXTemplate, sizeof(KPXTemplate) / sizeof(CK_ATTRIBUTE), &hKPX);
			if (rv != CKR_OK) {
				FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
				goto err;
			}
		}

		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, ulObjectFind);
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
	}}

err:
	if (hSession)
	{
		g_FunctionPtr->C_CloseSession(hSession);
	}

	IN_FreeLibrary();

	return rv;

}

int RT_P11_API_SetZMMetas(
	unsigned char *pAuthKey, int uiAuthKeyLen,
	char *pSecID, int uiSecIDLen,
	unsigned char szR1[32],unsigned char szR2[32], 
	unsigned char *pZMP, int uiZMPLen,
	unsigned char *pSignKey, int uiSignKeyLen,
	unsigned char *pCryptKey, int uiCryptKeyLen,
	unsigned char *pExchangeKey, int uiExchangeKeyLen,
	char * pszPIN, unsigned int * pulRetry
	)
{
	CK_RV rv = CKR_OK;

	CK_ULONG ulSlotID = 0;
	CK_ULONG ulAuthSlotID = 0;
	CK_SLOT_ID szSlotID[256];
	CK_ULONG ulSlotCount = 256;
	unsigned char szR3[32] = {0};
	int i = 0;
	CK_SESSION_HANDLE hSession = NULL_PTR;

	IN_LoadLibrary();

	ulSlotCount = sizeof(szSlotID)/sizeof(CK_SLOT_ID);
	rv = g_FunctionPtr->C_GetSlotList(bTrue, szSlotID, &ulSlotCount);
	if(rv != CKR_OK)
	{
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
		goto err;
	}

	FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);

	ulAuthSlotID = atoi((char *) pAuthKey);

	for(i = 0; i < ulSlotCount; i++)
	{
		if (szSlotID[i] == ulAuthSlotID)
		{
			continue;
		}
		else
		{
			ulSlotID = szSlotID[i];
			break;
		}
	}

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)pSecID, strlen(pSecID));

	rv = g_FunctionPtr->C_OpenSession(ulSlotID, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession);
	if (rv != CKR_OK) {
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
		goto err;
	}

	rv = g_FunctionPtr->C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR)pszPIN, strlen(pszPIN));
	if (rv!=CKR_OK && rv!=CKR_USER_ALREADY_LOGGED_IN) {
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
		goto err;
	}

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)pSignKey, uiSignKeyLen);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)pCryptKey, uiCryptKeyLen);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)pExchangeKey, uiExchangeKeyLen);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)pZMP, uiZMPLen);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)szR1, 32);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)szR2, 32);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)szR3, 32);

	// c1 encrypt key and zmp
	{

#if 1
		CK_OBJECT_CLASS objectClass = CKO_SECRET_KEY;
		CK_KEY_TYPE keyType = CKK_ZYJM;
		CK_OBJECT_HANDLE hKey = NULL_PTR;
		CK_ATTRIBUTE KeyTemplate[] = {
			{CKA_CLASS, &objectClass, sizeof(objectClass)},
			{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
			{CKA_TOKEN, &bFalse, sizeof(bFalse)},
			{CKA_ID, "temp_key", strlen("temp_key")},
			{CKA_ENCRYPT, &bTrue, sizeof(bTrue)},
			{CKA_VALUE, szR1, 32}
		};

		CK_ULONG ulLen = 0;

		CK_MECHANISM mech = {CKM_ZYJM_ECB, NULL, 0};

#else
		CK_OBJECT_CLASS objectClass = CKO_SECRET_KEY;
		CK_KEY_TYPE keyType = CKK_SM1;
		CK_OBJECT_HANDLE hKey = NULL_PTR;
		CK_ATTRIBUTE KeyTemplate[] = {
			{CKA_CLASS, &objectClass, sizeof(objectClass)},
			{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
			{CKA_TOKEN, &bFalse, sizeof(bFalse)},
			{CKA_ID, "temp_key", strlen("temp_key")},
			{CKA_ENCRYPT, &bTrue, sizeof(bTrue)},
			{CKA_VALUE, szR1, 16}
		};

		CK_ULONG ulLen = 0;

		CK_MECHANISM mech = {CKM_SM1_ECB, NULL, 0};
#endif

		rv = g_FunctionPtr->C_CreateObject(hSession, KeyTemplate, sizeof(KeyTemplate) / sizeof(CK_ATTRIBUTE), &hKey);
		if (rv != CKR_OK) {
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);

			goto err;
		}

		rv = g_FunctionPtr->C_EncryptInit(hSession, &mech, hKey);
		if (rv != CKR_OK) {
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
			goto err;
		}
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);

		ulLen = uiZMPLen;

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
		FILE_LOG_HEX(file_log_name, (unsigned char *)pZMP, ulLen);

		rv = g_FunctionPtr->C_Encrypt(hSession, pZMP, ulLen, pZMP, &ulLen);
		if (rv != CKR_OK) {
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
			goto err;
		}
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);


		rv = g_FunctionPtr->C_EncryptInit(hSession, &mech, hKey);
		if (rv != CKR_OK) {
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
			goto err;
		}
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);

		ulLen = 64;
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
		FILE_LOG_HEX(file_log_name, (unsigned char *)pSignKey  + 4 + 2 * GM_ECC_512_BYTES_LEN + 4, ulLen);
		rv = g_FunctionPtr->C_Encrypt(hSession, pSignKey + 4 + 2 * GM_ECC_512_BYTES_LEN + 4 , ulLen, pSignKey + 4 + 2 * GM_ECC_512_BYTES_LEN + 4, &ulLen);
		if (rv != CKR_OK) {
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
			goto err;
		}
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);

		rv = g_FunctionPtr->C_EncryptInit(hSession, &mech, hKey);
		if (rv != CKR_OK) {
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
			goto err;
		}
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);

		ulLen = 64;
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
		FILE_LOG_HEX(file_log_name, (unsigned char *)pCryptKey + 4 + 2 * GM_ECC_512_BYTES_LEN + 4, ulLen);
		rv = g_FunctionPtr->C_Encrypt(hSession, pCryptKey + 4 + 2 * GM_ECC_512_BYTES_LEN + 4 , ulLen, pCryptKey + 4 + 2 * GM_ECC_512_BYTES_LEN + 4, &ulLen);
		if (rv != CKR_OK) {
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
			goto err;
		}
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);

		rv = g_FunctionPtr->C_EncryptInit(hSession, &mech, hKey);
		if (rv != CKR_OK) {
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
			goto err;
		}
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);

		ulLen = 64;
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
		FILE_LOG_HEX(file_log_name, (unsigned char *)pExchangeKey + 4 + 2 * GM_ECC_512_BYTES_LEN + 4, ulLen);
		rv = g_FunctionPtr->C_Encrypt(hSession, pExchangeKey + 4 + 2 * GM_ECC_512_BYTES_LEN + 4 , ulLen, pExchangeKey + 4 + 2 * GM_ECC_512_BYTES_LEN + 4, &ulLen);
		if (rv != CKR_OK) {
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
			goto err;
		}
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);

		rv = g_FunctionPtr->C_DestroyObject(hSession,hKey);
		if (rv != CKR_OK) {
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
			goto err;
		}
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
	}

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)pSignKey, uiSignKeyLen);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)pCryptKey, uiCryptKeyLen);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)pExchangeKey, uiExchangeKeyLen);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)pZMP, uiZMPLen);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)szR1, 32);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)szR2, 32);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)szR3, 32);

	//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// 专密：互通密钥参数文件
	{{ // 创建文件
		// r1加密后的A类用户（KPA）：  0x02 + 0x31 + BE087F4168213C144B6DA3AACBF5D056BE087F4168213C144B6DA3AACBF5D056 + 0x32 + FAAAAE0892E71A69BAC81ECC3CCD3E1BFAAAAE0892E71A69BAC81ECC3CCD3E1B
		// r3: 0303030303030303030303030303030303030303030303030303030303030303
		// data: KPA||r3
		//unsigned char *pbKPX = (unsigned char*)"\x02\x31\xBE\x08\x7F\x41\x68\x21\x3C\x14\x4B\x6D\xA3\xAA\xCB\xF5\xD0\x56\xBE\x08\x7F\x41\x68\x21\x3C\x14\x4B\x6D\xA3\xAA\xCB\xF5\xD0\x56\x32\xFA\xAA\xAE\x08\x92\xE7\x1A\x69\xBA\xC8\x1E\xCC\x3C\xCD\x3E\x1B\xFA\xAA\xAE\x08\x92\xE7\x1A\x69\xBA\xC8\x1E\xCC\x3C\xCD\x3E\x1B\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03";
		//unsigned char *pbKPX = (unsigned char*)"\x02\x31\xBE\x08\x7F\x41\x68\x21\x3C\x14\x4B\x6D\xA3\xAA\xCB\xF5\xD0\x56\xBE\x08\x7F\x41\x68\x21\x3C\x14\x4B\x6D\xA3\xAA\xCB\xF5\xD0\x56\x32\xFA\xAA\xAE\x08\x92\xE7\x1A\x69\xBA\xC8\x1E\xCC\x3C\xCD\x3E\x1B\xFA\xAA\xAE\x08\x92\xE7\x1A\x69\xBA\xC8\x1E\xCC\x3C\xCD\x3E\x1B\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

		unsigned char szKPX[32*3 + 1 + 2];
		CK_ULONG ulKPXLen = 32*3 + 1 + 2;
		int i = 0;
		int pos = 0;
		CK_KEY_TYPE		keyType = CKK_GENERIC_SECRET;
		CK_OBJECT_CLASS SecretClass = CKO_SECRET_KEY;
		CK_ATTRIBUTE KPXTemplate[] = {
			{CKA_CLASS, &SecretClass, sizeof(SecretClass)},
			{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
			{CKA_TOKEN, &bTrue, sizeof(bTrue)},
			{CKA_ID, RT_ZM_ZMP, strlen(RT_ZM_ZMP)},
			{CKA_ENCRYPT, &bTrue, sizeof(bTrue)},
			{CKA_VALUE, (unsigned char *)szKPX, ulKPXLen}
		};
		CK_OBJECT_HANDLE hKPX=NULL_PTR;

		for(i = 0; i < 32; i++)
		{
			szR3[i] = szR1[i]^szR2[i];
		}

		switch(pSecID[0])
		{
		case '1':
			pos = 0;
			szKPX[pos] = 0x02;
			pos+=1;
			szKPX[pos] = 0x31;
			pos+=1;
			memcpy(szKPX+pos,pZMP+(0x31-0x31)*32,32);
			pos+=32;
			szKPX[pos] = 0x32;
			pos+=1;
			memcpy(szKPX+pos,pZMP+(0x32-0x31)*32,32);
			pos+=32;
			memcpy(szKPX+pos,szR3,32);
			pos+=32;
			KPXTemplate[5].ulValueLen = pos;
			break;
		case '2':
			pos = 0;
			szKPX[pos] = 0x02;
			pos+=1;
			szKPX[pos] = 0x32;
			pos+=1;
			memcpy(szKPX+pos,pZMP+(0x32-0x31)*32,32);
			pos+=32;
			szKPX[pos] = 0x33;
			pos+=1;
			memcpy(szKPX+pos,pZMP+(0x33-0x31)*32,32);
			pos+=32;
			memcpy(szKPX+pos,szR3,32);
			pos+=32;
			KPXTemplate[5].ulValueLen = pos;
			break;
		case '3':
			pos = 0;
			szKPX[pos] = 0x01;
			pos+=1;
			szKPX[pos] = 0x33;
			pos+=1;
			memcpy(szKPX+pos,pZMP+(0x33-0x31)*32,32);
			pos+=32;
			memcpy(szKPX+pos,szR3,32);
			pos+=32;
			KPXTemplate[5].ulValueLen = pos;
			break;
		case '4':
			pos = 0;
			break;
		default:
			pos = 0;
			break;
		}

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
		FILE_LOG_HEX(file_log_name, (unsigned char *)szKPX, pos);

		rv = g_FunctionPtr->C_CreateObject(hSession, KPXTemplate, sizeof(KPXTemplate) / sizeof(CK_ATTRIBUTE), &hKPX);
		if (rv != CKR_OK) {
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
			
			goto err;
		}
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
		
	}}

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)pSignKey, uiSignKeyLen);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)pCryptKey, uiCryptKeyLen);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)pExchangeKey, uiExchangeKeyLen);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)pZMP, uiZMPLen);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)szR1, 32);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)szR2, 32);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)szR3, 32);


	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// 专密
	{{ // ECC512签名密钥对

		CK_OBJECT_CLASS PubClass = CKO_PUBLIC_KEY;
		CK_OBJECT_CLASS PrivateClass = CKO_PRIVATE_KEY;

		CK_KEY_TYPE KeyType = CKK_ECC512;
		CK_ULONG ulBits = 512;

		CK_ULONG ulPubKeyCount, ulPriKeyCount;

		CK_OBJECT_HANDLE hPubKey = NULL;
		CK_OBJECT_HANDLE hPriKey = NULL;

		CK_ATTRIBUTE ECC512CreatePublicKeyTemplate[] = {
			{CKA_CLASS, &PubClass, sizeof(PubClass)},
			{CKA_KEY_TYPE, &KeyType, sizeof(KeyType)},
			{CKA_ID,    RT_ZM_SIGN, strlen(RT_ZM_SIGN)}, 
			{CKA_TOKEN, &bTrue, sizeof(bTrue)},
			{CKA_PRIVATE, &bFalse, sizeof(bFalse)},
			{CKA_ENCRYPT, &bTrue, sizeof(bTrue)},
			{CKA_VERIFY, &bTrue, sizeof(bTrue)},
			{CKA_ECC512_PUBLIC_X, pSignKey + 4, 64},
			{CKA_ECC512_PUBLIC_Y, pSignKey + 4 + GM_ECC_512_BYTES_LEN, 64},
			{CKA_ECC512_BITS, &ulBits, sizeof (ulBits)}
		};

		CK_ATTRIBUTE ECC512CreatePrivateKeyTemplate[] = {
			{CKA_CLASS, &PrivateClass, sizeof(PrivateClass)},
			{CKA_KEY_TYPE, &KeyType, sizeof(KeyType)},
			{CKA_ID,    RT_ZM_SIGN, strlen(RT_ZM_SIGN)}, 
			{CKA_TOKEN, &bTrue, sizeof(bTrue)},
			{CKA_PRIVATE, &bTrue, sizeof(bTrue)},
			{CKA_DECRYPT, &bTrue, sizeof(bTrue)},
			{CKA_SIGN, &bTrue, sizeof(bTrue)},
			{CKA_ECC512_PUBLIC_X, pSignKey + 4, 64},
			{CKA_ECC512_PUBLIC_Y, pSignKey + 4 + GM_ECC_512_BYTES_LEN, 64},
			{CKA_ECC512_BITS, &ulBits, sizeof (ulBits)},
			{CKA_ECC512_PRIVATE_KEY, pSignKey + 4 + 2 * GM_ECC_512_BYTES_LEN + 4, GM_ECC_512_BYTES_LEN}
		};
		ulPubKeyCount = sizeof(ECC512CreatePublicKeyTemplate) / sizeof(CK_ATTRIBUTE);
		ulPriKeyCount = sizeof(ECC512CreatePrivateKeyTemplate) / sizeof(CK_ATTRIBUTE);

		rv = g_FunctionPtr->C_CreateObject(hSession, ECC512CreatePublicKeyTemplate, ulPubKeyCount, &hPubKey);
		if (rv != CKR_OK) {
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
			
			goto err;
		}
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);

		rv = g_FunctionPtr->C_CreateObject(hSession, ECC512CreatePrivateKeyTemplate, ulPriKeyCount, &hPriKey);
		if (rv != CKR_OK) {
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
			
			goto err;
		}
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
		
	}}

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// 专密
	{{ // ECC512加密密钥对

		CK_OBJECT_CLASS PubClass = CKO_PUBLIC_KEY;
		CK_OBJECT_CLASS PrivateClass = CKO_PRIVATE_KEY;

		CK_KEY_TYPE KeyType = CKK_ECC512;
		CK_ULONG ulBits = 512;

		CK_ULONG ulPubKeyCount, ulPriKeyCount;

		CK_OBJECT_HANDLE hPubKey = NULL;
		CK_OBJECT_HANDLE hPriKey = NULL;

		CK_ATTRIBUTE ECC512CreatePublicKeyTemplate[] = {
			{CKA_CLASS, &PubClass, sizeof(PubClass)},
			{CKA_KEY_TYPE, &KeyType, sizeof(KeyType)},
			{CKA_ID,    RT_ZM_ENC, strlen(RT_ZM_ENC)}, 
			{CKA_TOKEN, &bTrue, sizeof(bTrue)},
			{CKA_PRIVATE, &bFalse, sizeof(bFalse)},
			{CKA_ENCRYPT, &bTrue, sizeof(bTrue)},
			{CKA_VERIFY, &bTrue, sizeof(bTrue)},
			{CKA_ECC512_PUBLIC_X, pCryptKey + 4, 64},
			{CKA_ECC512_PUBLIC_Y, pCryptKey + 4 + GM_ECC_512_BYTES_LEN, 64},
			{CKA_ECC512_BITS, &ulBits, sizeof (ulBits)}
		};

		CK_ATTRIBUTE ECC512CreatePrivateKeyTemplate[] = {
			{CKA_CLASS, &PrivateClass, sizeof(PrivateClass)},
			{CKA_KEY_TYPE, &KeyType, sizeof(KeyType)},
			{CKA_ID,    RT_ZM_ENC, strlen(RT_ZM_ENC)}, 
			{CKA_TOKEN, &bTrue, sizeof(bTrue)},
			{CKA_PRIVATE, &bTrue, sizeof(bTrue)},
			{CKA_DECRYPT, &bTrue, sizeof(bTrue)},
			{CKA_SIGN, &bTrue, sizeof(bTrue)},
			{CKA_ECC512_PUBLIC_X, pCryptKey + 4, 64},
			{CKA_ECC512_PUBLIC_Y, pCryptKey + 4 + GM_ECC_512_BYTES_LEN, 64},
			{CKA_ECC512_BITS, &ulBits, sizeof (ulBits)},
			{CKA_ECC512_PRIVATE_KEY, pCryptKey + 4 + 2 * GM_ECC_512_BYTES_LEN + 4, GM_ECC_512_BYTES_LEN}
		};
		ulPubKeyCount = sizeof(ECC512CreatePublicKeyTemplate) / sizeof(CK_ATTRIBUTE);
		ulPriKeyCount = sizeof(ECC512CreatePrivateKeyTemplate) / sizeof(CK_ATTRIBUTE);

		rv = g_FunctionPtr->C_CreateObject(hSession, ECC512CreatePublicKeyTemplate, ulPubKeyCount, &hPubKey);
		if (rv != CKR_OK) {
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
			goto err;
		}
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);

		rv = g_FunctionPtr->C_CreateObject(hSession, ECC512CreatePrivateKeyTemplate, ulPriKeyCount, &hPriKey);
		if (rv != CKR_OK) {
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
			
			goto err;
		}
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
	}}

	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// 专密
	{{ // ECC512交换钥对

		CK_OBJECT_CLASS PubClass = CKO_PUBLIC_KEY;
		CK_OBJECT_CLASS PrivateClass = CKO_PRIVATE_KEY;

		CK_KEY_TYPE KeyType = CKK_ECC512;
		CK_ULONG ulBits = 512;

		CK_ULONG ulPubKeyCount, ulPriKeyCount;

		CK_OBJECT_HANDLE hPubKey = NULL;
		CK_OBJECT_HANDLE hPriKey = NULL;

		CK_ATTRIBUTE ECC512CreatePublicKeyTemplate[] = {
			{CKA_CLASS, &PubClass, sizeof(PubClass)},
			{CKA_KEY_TYPE, &KeyType, sizeof(KeyType)},
			{CKA_ID,    RT_ZM_EXC, strlen(RT_ZM_EXC)}, 
			{CKA_TOKEN, &bTrue, sizeof(bTrue)},
			{CKA_PRIVATE, &bFalse, sizeof(bFalse)},
			{CKA_ENCRYPT, &bTrue, sizeof(bTrue)},
			{CKA_VERIFY, &bTrue, sizeof(bTrue)},
			{CKA_ECC512_PUBLIC_X, pExchangeKey + 4, 64},
			{CKA_ECC512_PUBLIC_Y, pExchangeKey + 4 + GM_ECC_512_BYTES_LEN, 64},
			{CKA_ECC512_BITS, &ulBits, sizeof (ulBits)}
		};

		CK_ATTRIBUTE ECC512CreatePrivateKeyTemplate[] = {
			{CKA_CLASS, &PrivateClass, sizeof(PrivateClass)},
			{CKA_KEY_TYPE, &KeyType, sizeof(KeyType)},
			{CKA_ID,    RT_ZM_EXC, strlen(RT_ZM_EXC)}, 
			{CKA_TOKEN, &bTrue, sizeof(bTrue)},
			{CKA_PRIVATE, &bTrue, sizeof(bTrue)},
			{CKA_DECRYPT, &bTrue, sizeof(bTrue)},
			{CKA_SIGN, &bTrue, sizeof(bTrue)},
			{CKA_ECC512_PUBLIC_X, pExchangeKey + 4, 64},
			{CKA_ECC512_PUBLIC_Y, pExchangeKey + 4 + GM_ECC_512_BYTES_LEN, 64},
			{CKA_ECC512_BITS, &ulBits, sizeof (ulBits)},
			{CKA_ECC512_PRIVATE_KEY, pExchangeKey + 4 + 2 * GM_ECC_512_BYTES_LEN + 4, GM_ECC_512_BYTES_LEN}
		};
		ulPubKeyCount = sizeof(ECC512CreatePublicKeyTemplate) / sizeof(CK_ATTRIBUTE);
		ulPriKeyCount = sizeof(ECC512CreatePrivateKeyTemplate) / sizeof(CK_ATTRIBUTE);

		rv = g_FunctionPtr->C_CreateObject(hSession, ECC512CreatePublicKeyTemplate, ulPubKeyCount, &hPubKey);
		if (rv != CKR_OK) {
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
			
			goto err;
		}
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
		

		rv = g_FunctionPtr->C_CreateObject(hSession, ECC512CreatePrivateKeyTemplate, ulPriKeyCount, &hPriKey);
		if (rv != CKR_OK) {
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
			
			goto err;
		}
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
		
	}}

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)pSignKey, uiSignKeyLen);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)pCryptKey, uiCryptKeyLen);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)pExchangeKey, uiExchangeKeyLen);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)pZMP, uiZMPLen);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)szR1, 32);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)szR2, 32);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)szR3, 32);


err:
	if (hSession)
	{
		g_FunctionPtr->C_CloseSession(hSession);
	}

	IN_FreeLibrary();

	return rv;
}

int RT_P11_API_SetZMCerts(
	unsigned char *pAuthKey, int uiAuthKeyLen,
	unsigned char *pSignCert, int uiSignCertLen,
	unsigned char *pCryptCert, int uiCryptCertLen,
	unsigned char *pExchangeCert, int uiExchangeCertLen,
	char * pszPIN, unsigned int * pulRetry
	)
{
	CK_RV rv = CKR_OK;

	CK_ULONG ulSlotID = 0;
	CK_ULONG ulAuthSlotID = 0;
	CK_SLOT_ID szSlotID[256];
	CK_ULONG ulSlotCount = 256;
	int i = 0;
	CK_SESSION_HANDLE hSession = NULL_PTR;

	IN_LoadLibrary();

	ulSlotCount = sizeof(szSlotID)/sizeof(CK_SLOT_ID);

	rv = g_FunctionPtr->C_GetSlotList(bTrue, szSlotID, &ulSlotCount);
	if(rv != CKR_OK)
	{
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
		goto err;
	}

	FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);

	ulAuthSlotID = atoi((char *) pAuthKey);

	for(i = 0; i < ulSlotCount; i++)
	{
		if (szSlotID[i] == ulAuthSlotID)
		{
			continue;
		}
		else
		{
			ulSlotID = szSlotID[i];
			break;
		}
	}

	rv = g_FunctionPtr->C_OpenSession(ulSlotID, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession);
	if (rv != CKR_OK) {
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
		goto err;
	}

	rv = g_FunctionPtr->C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR)pszPIN, strlen(pszPIN));
	if (rv!=CKR_OK && rv!=CKR_USER_ALREADY_LOGGED_IN) {
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
		goto err;
	}

	{
		CK_OBJECT_CLASS DataClass = CKO_CERTIFICATE;
		CK_BBOOL True = TRUE;
		CK_ULONG ulObjectCount = 0;
		CK_OBJECT_HANDLE hObjects[16];
		CK_CERTIFICATE_TYPE CertType = CKC_X_509;
		CK_UTF8CHAR CertSubject[] = "ECC512 X509 Certificate";

		CK_ATTRIBUTE certTemplateSign[] = {
			{CKA_CLASS, &DataClass , sizeof(DataClass)},
			{CKA_CERTIFICATE_TYPE, &CertType, sizeof(CertType)},
			{CKA_LABEL,RT_ZM_SIGN , strlen(RT_ZM_SIGN)},
			{CKA_SUBJECT, CertSubject, sizeof(CertSubject)-1},
			{CKA_TOKEN, &True, sizeof(True)},
			{CKA_ID,RT_ZM_SIGN , strlen(RT_ZM_SIGN)},
			{CKA_VALUE, pSignCert,uiSignCertLen}
		};

		CK_ATTRIBUTE certTemplateEnc[] = {
			{CKA_CLASS, &DataClass , sizeof(DataClass)},
			{CKA_CERTIFICATE_TYPE, &CertType, sizeof(CertType)},
			{CKA_LABEL ,RT_ZM_ENC , strlen(RT_ZM_ENC)},
			{CKA_SUBJECT, CertSubject, sizeof(CertSubject)-1},
			{CKA_TOKEN, &True, sizeof(True)},
			{CKA_ID,RT_ZM_ENC , strlen(RT_ZM_ENC)},
			{CKA_VALUE, pCryptCert,uiCryptCertLen}
		};

		CK_ATTRIBUTE certTemplateExc[] = {
			{CKA_CLASS, &DataClass , sizeof(DataClass)},
			{CKA_CERTIFICATE_TYPE, &CertType, sizeof(CertType)},
			{CKA_LABEL, RT_ZM_EXC , strlen(RT_ZM_EXC)},
			{CKA_SUBJECT, CertSubject, sizeof(CertSubject)-1},
			{CKA_TOKEN, &True, sizeof(True)},
			{CKA_ID,RT_ZM_EXC , strlen(RT_ZM_EXC)},
			{CKA_VALUE, pExchangeCert,uiExchangeCertLen}
		};

		rv = g_FunctionPtr->C_CreateObject(hSession, certTemplateSign, sizeof(certTemplateSign)/sizeof(CK_ATTRIBUTE),hObjects);
		if (rv != CKR_OK)
		{
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
			goto err;
		}

		rv = g_FunctionPtr->C_CreateObject(hSession, certTemplateEnc, sizeof(certTemplateEnc)/sizeof(CK_ATTRIBUTE),hObjects);
		if (rv != CKR_OK)
		{
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
			goto err;
		}

		rv = g_FunctionPtr->C_CreateObject(hSession, certTemplateExc, sizeof(certTemplateExc)/sizeof(CK_ATTRIBUTE),hObjects);
		if (rv != CKR_OK)
		{
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
			goto err;
		}
	}	

err:
	if (hSession)
	{
		g_FunctionPtr->C_CloseSession(hSession);
	}

	FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);

	IN_FreeLibrary();

	return rv;
}

int RT_P11_API_GetCertCount(
	unsigned char *pAuthKey, int uiAuthKeyLen,
	unsigned int *CertCount,
	char * pszPIN, unsigned int * pulRetry
	)
{
	CK_RV rv = CKR_OK;

	CK_ULONG ulSlotID = 0;
	CK_ULONG ulAuthSlotID = 0;
	CK_SLOT_ID szSlotID[256];
	CK_ULONG ulSlotCount = 256;
	int i = 0;
	CK_SESSION_HANDLE hSession = NULL_PTR;

	IN_LoadLibrary();

	ulSlotCount = sizeof(szSlotID)/sizeof(CK_SLOT_ID);

	rv = g_FunctionPtr->C_GetSlotList(bTrue, szSlotID, &ulSlotCount);
	if(rv != CKR_OK)
	{
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
		goto err;
	}

	FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);

	ulAuthSlotID = atoi((char *) pAuthKey);

	*CertCount = 0;

	for(i = 0; i < ulSlotCount; i++)
	{
		if (szSlotID[i] == ulAuthSlotID)
		{
			continue;
		}
		else
		{
			ulSlotID = szSlotID[i];
			break;
		}
	}

	rv = g_FunctionPtr->C_OpenSession(ulSlotID, CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession);
	if (rv != CKR_OK) {
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
		goto err;
	}

	//rv = g_FunctionPtr->C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR)pszPIN, strlen(pszPIN));
	//if (rv!=CKR_OK && rv!=CKR_USER_ALREADY_LOGGED_IN) {
	//	FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, rv);
	//	goto err;
	//}

	{
		CK_OBJECT_CLASS DataClass = CKO_CERTIFICATE;
		CK_BBOOL True = TRUE;
		CK_ULONG ulObjectCount = 0;
		CK_OBJECT_HANDLE hObjects[16], hUserInfoObj = NULL_PTR;

		CK_ATTRIBUTE searchTemplate[] = {
			{CKA_CLASS, &DataClass , sizeof(DataClass)},
			{CKA_TOKEN, &True, sizeof(True)},
		};

		rv = g_FunctionPtr->C_FindObjectsInit(hSession, searchTemplate, sizeof(searchTemplate)/sizeof(CK_ATTRIBUTE));
		if (rv != CKR_OK)
		{
			goto err;
		}
		ulObjectCount = sizeof(hObjects)/sizeof(CK_OBJECT_HANDLE);
		rv = g_FunctionPtr->C_FindObjects(hSession, hObjects, sizeof(hObjects)/sizeof(CK_OBJECT_HANDLE), &ulObjectCount);
		g_FunctionPtr->C_FindObjectsFinal(hSession);

		if (rv != CKR_OK)
		{
			goto err;
		}

		*CertCount = ulObjectCount;
	}	

err:
	if (hSession)
	{
		g_FunctionPtr->C_CloseSession(hSession);
	}

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_HEX(file_log_name, (unsigned char *)CertCount, 4);

	IN_FreeLibrary();

	return rv;
}
