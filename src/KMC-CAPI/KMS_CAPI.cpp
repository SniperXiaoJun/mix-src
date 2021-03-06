#include "KMS_CAPI.h"
#include "FILE_LOG.h"
#include "o_all_type_def.h"
#include "o_all_func_def.h"
#include <string.h>

char DEFAULT_CONTAINER_SM2[] = "RT_SM_CON";
char DEFAULT_CONTAINER_ECC512[] = "ContainerECC512";
char DEFAULT_APPLICATION[] = "DEFAULT_APPLICATION";
char DEFAULT_FILE_NAME[] = "DEFAULT_FILE_NAME";

unsigned int CAPI_KEY_SetStr(char * strIN)
{
	FILE_LOG_FMT(file_log_name,"%s %d %s",__FUNCTION__ , __LINE__, strIN);

	return 0;
}

unsigned int CAPI_KEY_GetStr(char * strOut)
{
	memcpy(strOut,"abcd",5);

	return 0;
}


ULONG CAPI_KEY_DevAuth(HANDLE hDevSKF)
{
	// 第一步设备认证
	unsigned char	bRandom[16], bAuthData[16];
	unsigned long	ulRandomLen;
	ULONG ulAuthDataLen;
	BLOCKCIPHERPARAM EncryptParam;
	unsigned char	bSymKey[16];
	HANDLE			hSymKey=NULL;
	ULONG ulRet = 0;
	DEVINFO			DevInfo;




	for (int iTry =0; iTry < 2; iTry++)
	{
		if (iTry == 0)
		{
			for (int i = 0; i < 16; i++)
			{
				bSymKey[i] = '0' + i%8 + 1;
			}
		}
		else
		{
			for (int i = 0; i < 16; i++)
			{
				bSymKey[i] = 0xFF;
			}
		}

		// 取16字节随机数
		ulRandomLen = sizeof(bRandom);
		ulRet = SKF_GenRandom(hDevSKF, bRandom, ulRandomLen);
		if(ulRet != 0)
		{
			::FILE_LOG_STRING(file_log_name,"SKF_GenRandom");
			continue;
		}

		ulRet = SKF_GetDevInfo(hDevSKF, &DevInfo);
		if(ulRet != 0)
		{
			::FILE_LOG_STRING(file_log_name,"SKF_GetDevInfo");
			continue;
		}
		// 加密随机化
		// 默认外部认证密钥为：1234567812345678
		//memcpy(bSymKey, (unsigned char*)"\x31\x32\x33\x34\x35\x36\x37\x38\x31\x32\x33\x34\x35\x36\x37\x38", 16);

		ulRet = SKF_SetSymmKey(hDevSKF, bSymKey, DevInfo.DevAuthAlgId, &hSymKey);
		if(ulRet != 0)
		{
			::FILE_LOG_STRING(file_log_name,"SKF_SetSymmKey");
			continue;
		}

		// 加密初始化
		EncryptParam.PaddingType = 0;
		ulRet = SKF_EncryptInit(hSymKey, EncryptParam);
		if(ulRet != 0)
		{
			::FILE_LOG_STRING(file_log_name,"SKF_EncryptInit");
			continue;
		}

		// 加密随机数
		ulAuthDataLen = sizeof(bAuthData);
		memset(bAuthData, 0x00, ulAuthDataLen);
		ulRet = SKF_Encrypt(hSymKey, bRandom, ulRandomLen, bAuthData, &ulAuthDataLen);
		if(ulRet != 0)
		{
			::FILE_LOG_STRING(file_log_name,"SKF_Encrypt");
			continue;
		}

		// 外部认证
		ulRet = SKF_DevAuth(hDevSKF, bAuthData, ulAuthDataLen);
		if(ulRet != 0)
		{
			::FILE_LOG_STRING(file_log_name,"SKF_DevAuth");
			continue;
		}
		else
		{
			break;
		}


	}
err:

	return ulRet;
}

unsigned int CAPI_GetMulStringCount(char * pszMulString, int * pulCount)
{
	int i = 0;

	int ulCount = 0;

	char * ptr = pszMulString;

	for (ptr = pszMulString;*ptr;)
	{
		ptr += strlen(ptr);
		ptr++;
		ulCount++;
	}

	*pulCount = ulCount;

	return 0;
}


char * CAPI_KEY_GetSubStringPtr(char * pszMulString, char * pszSubString)
{
	char * ptr = pszMulString;

	for (ptr = pszMulString;*ptr;)
	{
		if (strstr(ptr,pszSubString))
		{
			return ptr;
		}

		ptr += strlen(ptr);
		ptr++;
	}

	return NULL;
}




ULONG CAPI_KEY_ConnectDev(char * pszDevList, char * pszKeyOn, int ulKeyTarget, HANDLE * phDevSKF)
{
	if (OPE_USB_TARGET_SELF == ulKeyTarget)
	{
		return SKF_ConnectDev(pszKeyOn,phDevSKF);
	}
	else
	{
		while (0 == strcmp(pszDevList,pszKeyOn))
		{
			pszDevList += strlen(pszDevList);
			pszDevList += 1;
		}

		return SKF_ConnectDev(pszDevList,phDevSKF);
	}
}


unsigned int CAPI_KEY_GetKeyCount(int * pulKeyCount)
{
	unsigned int ulRet = 0;
	char szDevNameLists[BUFFER_LEN_1K] = {0};

	ULONG ulDevNameLists = BUFFER_LEN_1K;

	ECCSIGNATUREBLOB stSigBlob = {0};

	int ulKeyCount = 0;

	ulRet = SKF_EnumDev(TRUE,szDevNameLists,&ulDevNameLists);

	if(ulRet)
	{
		goto err;
	}

	CAPI_GetMulStringCount(szDevNameLists, &ulKeyCount);

err:
	* pulKeyCount = ulKeyCount;

	return 0;
}

unsigned int CAPI_KEY_SignDigest(char * pszKeyOn,int ulKeyTarget, char * pszPIN, unsigned char *pbDigest, unsigned char * pbSigValue, unsigned int * pulRetry)
{
	unsigned int ulRet = 0;

	char szDevNameLists[BUFFER_LEN_1K] = {0};
	char szAppNameLists[BUFFER_LEN_1K] = {0};
	char szConNameLists[BUFFER_LEN_1K] = {0};

	HANDLE hDevSKF = NULL;
	HANDLE hAppSKF = NULL;
	HANDLE hConSKF = NULL;

	ULONG ulDevNameLists = BUFFER_LEN_1K;
	ULONG ulAppNameLists = BUFFER_LEN_1K;
	ULONG ulConNameLists = BUFFER_LEN_1K;

	ECCSIGNATUREBLOB stSigBlob = {0};

	int ulKeyCount = 0;

	ulRet = SKF_EnumDev(TRUE,szDevNameLists,&ulDevNameLists);

	if(ulRet)
	{
		goto err;
	}

	CAPI_GetMulStringCount(szDevNameLists, &ulKeyCount);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_EnumDev");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "ulDevNameLists");
	FILE_LOG_NUMBER(file_log_name,(long)ulDevNameLists);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "szDevNameLists");
	FILE_LOG_STRING(file_log_name,szDevNameLists);

	if (0 == ulKeyCount)
	{
		ulRet = OPE_ERR_DEV_NUMBER_ZERO;  // 未插入设备
		goto err;
	}

	if (OPE_USB_TARGET_SELF == ulKeyTarget)
	{
		if (1 != ulKeyCount)
		{
			ulRet = OPE_ERR_DEV_NUMBER_ERR;  // 设备个数不正确
			goto err;
		}

		strcpy(pszKeyOn,szDevNameLists);
	}
	else
	{
		//初始化审计员|操作员
		if (2 != ulKeyCount)
		{
			ulRet = OPE_ERR_DEV_NUMBER_ERR;  // 设备个数不正确
			goto err;
		}
	}

	// 打开设备
	ulRet = CAPI_KEY_ConnectDev(szDevNameLists,pszKeyOn,ulKeyTarget,&hDevSKF);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_ConnectDev");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if(ulRet)
	{
		goto err;
	}

	ulRet = SKF_EnumApplication(hDevSKF,szAppNameLists, &ulAppNameLists);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_EnumApplication");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if (ulAppNameLists < 2)
	{
		ulRet = OPE_ERR_OPEN_APPLICATION;
		goto err;
	}
	else
	{
		ulRet = SKF_OpenApplication(hDevSKF, szAppNameLists,&hAppSKF);
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_OpenApplication");
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, szAppNameLists);
		FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	}


	if(ulRet)
	{
		goto err;
	}


	ulRet = SKF_VerifyPIN(hAppSKF, 1, pszPIN,(ULONG *)pulRetry);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_VerifyPIN");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if(ulRet)
	{
		goto err;
	}


	// 枚举容器
	ulRet = SKF_EnumContainer(hAppSKF,szConNameLists,&ulConNameLists);
	if(ulRet)
	{
		goto err;
	}
	// 创建或打开容器
	if (NULL == CAPI_KEY_GetSubStringPtr(szConNameLists,DEFAULT_CONTAINER_SM2))
	{
		ulRet = SKF_CreateContainer(hAppSKF, DEFAULT_CONTAINER_SM2, &hConSKF);
	}
	else
	{
		ulRet = SKF_OpenContainer(hAppSKF, DEFAULT_CONTAINER_SM2, &hConSKF);
	}

	if(ulRet)
	{
		goto err;
	}
	
	ulRet = SKF_ECCSignData(hConSKF,pbDigest,SM3_DIGEST_LEN,&stSigBlob);
	if(ulRet)
	{
		goto err;
	}

	memcpy(pbSigValue,stSigBlob.r  + SM2_BYTES_LEN, SM2_BYTES_LEN);
	memcpy(pbSigValue + SM2_BYTES_LEN,stSigBlob.s  + SM2_BYTES_LEN, SM2_BYTES_LEN);

err:

	if(hConSKF)
	{
		SKF_CloseContainer(hConSKF);
	}

	if (hAppSKF)
	{
		SKF_CloseApplication(hAppSKF);
	}
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if (hDevSKF)
	{
		SKF_DisConnectDev(hDevSKF);
	}
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);

	return ulRet;
}


// 设置初始化PIN
unsigned int CAPI_KEY_SetPin(/*IN OUT*/char * pszKeyOn, int ulKeyTarget, char * pszPINAdmin,char * pszPINUser)
{
	unsigned long ulRet;

	char szDevNameLists[BUFFER_LEN_1K] = {0};

	HANDLE hDevSKF = NULL;
	HANDLE hAppSKF = NULL;

	ULONG ulDevNameLists = BUFFER_LEN_1K;

	int ulKeyCount = 0;


	ulRet = SKF_EnumDev(TRUE,szDevNameLists,&ulDevNameLists);

	if(ulRet)
	{
		goto err;
	}

	CAPI_GetMulStringCount(szDevNameLists, &ulKeyCount);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_EnumDev");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "ulDevNameLists");
	FILE_LOG_NUMBER(file_log_name,(long)ulDevNameLists);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "szDevNameLists");
	FILE_LOG_STRING(file_log_name,szDevNameLists);

	if (0 == ulKeyCount)
	{
		ulRet = OPE_ERR_DEV_NUMBER_ZERO;  // 未插入设备
		goto err;
	}

	if (OPE_USB_TARGET_SELF == ulKeyTarget)
	{
		if (1 != ulKeyCount)
		{
			ulRet = OPE_ERR_DEV_NUMBER_ERR;  // 设备个数不正确
			goto err;
		}

		strcpy(pszKeyOn,szDevNameLists);
	}
	else
	{
		//初始化审计员|操作员
		if (2 != ulKeyCount)
		{
			ulRet = OPE_ERR_DEV_NUMBER_ERR;  // 设备个数不正确
			goto err;
		}
	}

	// 打开设备
	ulRet = CAPI_KEY_ConnectDev(szDevNameLists,pszKeyOn,ulKeyTarget,&hDevSKF);
	if(ulRet)
	{
		goto err;
	}

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_ConnectDev");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);


	ulRet = CAPI_KEY_DevAuth(hDevSKF);
	if(ulRet)
	{
		goto err;
	}

	// 创建应用
	ulRet = SKF_CreateApplication(hDevSKF,DEFAULT_APPLICATION, pszPINAdmin,8,
		pszPINUser, 8, 0, &hAppSKF);

err:

	if (hAppSKF)
	{
		SKF_CloseApplication(hAppSKF);
	}

	if (hDevSKF)
	{
		SKF_DisConnectDev(hDevSKF);
	}

	return ulRet;
}

// 设置初始化PIN
unsigned int CAPI_KEY_ChgPin(/*IN OUT*/char * pszKeyOn, int ulKeyTarget,int ulFlag, char * pszPINOld,char * pszPINNew, unsigned int * pulRetry)
{
	unsigned int ulRet = 0;

	char szDevNameLists[BUFFER_LEN_1K] = {0};
	char szAppNameLists[BUFFER_LEN_1K] = {0};

	HANDLE hDevSKF = NULL;
	HANDLE hAppSKF = NULL;

	ULONG ulDevNameLists = BUFFER_LEN_1K;
	ULONG ulAppNameLists = BUFFER_LEN_1K;

	int ulKeyCount = 0;

	ulRet = SKF_EnumDev(TRUE,szDevNameLists,&ulDevNameLists);

	if(ulRet)
	{
		goto err;
	}

	CAPI_GetMulStringCount(szDevNameLists, &ulKeyCount);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_EnumDev");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "ulDevNameLists");
	FILE_LOG_NUMBER(file_log_name,(long)ulDevNameLists);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "szDevNameLists");
	FILE_LOG_STRING(file_log_name,szDevNameLists);

	if (0 == ulKeyCount)
	{
		ulRet = OPE_ERR_DEV_NUMBER_ZERO;  // 未插入设备
		goto err;
	}

	if (OPE_USB_TARGET_SELF == ulKeyTarget)
	{
		if (1 != ulKeyCount)
		{
			ulRet = OPE_ERR_DEV_NUMBER_ERR;  // 设备个数不正确
			goto err;
		}

		strcpy(pszKeyOn,szDevNameLists);
	}
	else
	{
		//初始化审计员|操作员
		if (2 != ulKeyCount)
		{
			ulRet = OPE_ERR_DEV_NUMBER_ERR;  // 设备个数不正确
			goto err;
		}
	}

	// 打开设备
	ulRet = CAPI_KEY_ConnectDev(szDevNameLists,pszKeyOn,ulKeyTarget,&hDevSKF);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_ConnectDev");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if(ulRet)
	{
		goto err;
	}

	ulRet = SKF_EnumApplication(hDevSKF,szAppNameLists, &ulAppNameLists);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_EnumApplication");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if (ulAppNameLists < 2)
	{
		ulRet = OPE_ERR_OPEN_APPLICATION;
		goto err;
	}
	else
	{
		ulRet = SKF_OpenApplication(hDevSKF, szAppNameLists,&hAppSKF);
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_OpenApplication");
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, szAppNameLists);
		FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	}


	if(ulRet)
	{
		goto err;
	}

	//ulRet = SKF_VerifyPIN(hAppSKF, 0, pszPINAdmin,(ULONG *)pulRetry);
	//FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_VerifyPIN");
	//FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	//if(ulRet)
	//{
	//	goto err;
	//}

	ulRet = SKF_ChangePIN(hAppSKF,ulFlag, pszPINOld,pszPINNew,(ULONG *)pulRetry);
	if(ulRet)
	{
		goto err;
	}

err:

	if (hAppSKF)
	{
		SKF_CloseApplication(hAppSKF);
	}
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if (hDevSKF)
	{
		SKF_DisConnectDev(hDevSKF);
	}
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);

	return ulRet;
}



unsigned int CAPI_KEY_UnlockPin(char * pszKeyOn,int ulKeyTarget, char * pszPINAdmin,char * pszPINUser, unsigned int * pulRetry)
{
	unsigned int ulRet = 0;

	char szDevNameLists[BUFFER_LEN_1K] = {0};
	char szAppNameLists[BUFFER_LEN_1K] = {0};

	HANDLE hDevSKF = NULL;
	HANDLE hAppSKF = NULL;

	ULONG ulDevNameLists = BUFFER_LEN_1K;
	ULONG ulAppNameLists = BUFFER_LEN_1K;

	int ulKeyCount = 0;

	ulRet = SKF_EnumDev(TRUE,szDevNameLists,&ulDevNameLists);

	if(ulRet)
	{
		goto err;
	}

	CAPI_GetMulStringCount(szDevNameLists, &ulKeyCount);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_EnumDev");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "ulDevNameLists");
	FILE_LOG_NUMBER(file_log_name,(long)ulDevNameLists);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "szDevNameLists");
	FILE_LOG_STRING(file_log_name,szDevNameLists);

	if (0 == ulKeyCount)
	{
		ulRet = OPE_ERR_DEV_NUMBER_ZERO;  // 未插入设备
		goto err;
	}

	if (OPE_USB_TARGET_SELF == ulKeyTarget)
	{
		if (1 != ulKeyCount)
		{
			ulRet = OPE_ERR_DEV_NUMBER_ERR;  // 设备个数不正确
			goto err;
		}

		strcpy(pszKeyOn,szDevNameLists);
	}
	else
	{
		//初始化审计员|操作员
		if (2 != ulKeyCount)
		{
			ulRet = OPE_ERR_DEV_NUMBER_ERR;  // 设备个数不正确
			goto err;
		}
	}

	// 打开设备
	ulRet = CAPI_KEY_ConnectDev(szDevNameLists,pszKeyOn,ulKeyTarget,&hDevSKF);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_ConnectDev");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if(ulRet)
	{
		goto err;
	}

	ulRet = SKF_EnumApplication(hDevSKF,szAppNameLists, &ulAppNameLists);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_EnumApplication");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if (ulAppNameLists < 2)
	{
		ulRet = OPE_ERR_OPEN_APPLICATION;
		goto err;
	}
	else
	{
		ulRet = SKF_OpenApplication(hDevSKF, szAppNameLists,&hAppSKF);
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_OpenApplication");
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, szAppNameLists);
		FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	}


	if(ulRet)
	{
		goto err;
	}

	//ulRet = SKF_VerifyPIN(hAppSKF, 0, pszPINAdmin,(ULONG *)pulRetry);
	//FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_VerifyPIN");
	//FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	//if(ulRet)
	//{
	//	goto err;
	//}

	ulRet = SKF_UnblockPIN(hAppSKF,pszPINAdmin,pszPINUser,(ULONG *)pulRetry);
	if(ulRet)
	{
		goto err;
	}
	
err:

	if (hAppSKF)
	{
		SKF_CloseApplication(hAppSKF);
	}
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if (hDevSKF)
	{
		SKF_DisConnectDev(hDevSKF);
	}
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);

	return ulRet;
}

// 设置Key类型
unsigned int CAPI_KEY_SetMeta(char * pszKeyOn, int ulKeyTarget, OPT_ST_USB_META * pMeta, char * pszPIN, unsigned int * pulRetry)
{
	unsigned int ulRet = 0;


	char szDevNameLists[BUFFER_LEN_1K] = {0};
	char szAppNameLists[BUFFER_LEN_1K] = {0};

	HANDLE hDevSKF = NULL;
	HANDLE hAppSKF = NULL;

	ULONG ulDevNameLists = BUFFER_LEN_1K;
	ULONG ulAppNameLists = BUFFER_LEN_1K;

	int ulKeyCount = 0;

	ulRet = SKF_EnumDev(TRUE,szDevNameLists,&ulDevNameLists);

	if(ulRet)
	{
		goto err;
	}

	CAPI_GetMulStringCount(szDevNameLists, &ulKeyCount);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_EnumDev");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "ulDevNameLists");
	FILE_LOG_NUMBER(file_log_name,(long)ulDevNameLists);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "szDevNameLists");
	FILE_LOG_STRING(file_log_name,szDevNameLists);

	if (0 == ulKeyCount)
	{
		ulRet = OPE_ERR_DEV_NUMBER_ZERO;  // 未插入设备
		goto err;
	}

	if (OPE_USB_TARGET_SELF == ulKeyTarget)
	{
		if (1 != ulKeyCount)
		{
			ulRet = OPE_ERR_DEV_NUMBER_ERR;  // 设备个数不正确
			goto err;
		}

		strcpy(pszKeyOn,szDevNameLists);
	}
	else
	{
		//初始化审计员|操作员
		if (2 != ulKeyCount)
		{
			ulRet = OPE_ERR_DEV_NUMBER_ERR;  // 设备个数不正确
			goto err;
		}
	}

	// 打开设备
	ulRet = CAPI_KEY_ConnectDev(szDevNameLists,pszKeyOn,ulKeyTarget,&hDevSKF);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_ConnectDev");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if(ulRet)
	{
		goto err;
	}

	ulRet = SKF_EnumApplication(hDevSKF,szAppNameLists, &ulAppNameLists);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_EnumApplication");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if (ulAppNameLists < 2)
	{
		ulRet = OPE_ERR_OPEN_APPLICATION;
		goto err;
	}
	else
	{
		ulRet = SKF_OpenApplication(hDevSKF, szAppNameLists,&hAppSKF);
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_OpenApplication");
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, szAppNameLists);
		FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	}


	if(ulRet)
	{
		goto err;
	}


	ulRet = SKF_VerifyPIN(hAppSKF, 1, pszPIN,(ULONG *)pulRetry);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_VerifyPIN");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if(ulRet)
	{
		goto err;
	}

	ulRet = SKF_DeleteFile(hAppSKF,DEFAULT_FILE_NAME);
	ulRet = SKF_CreateFile(hAppSKF,DEFAULT_FILE_NAME,BUFFER_LEN_1K,SECURE_ANYONE_ACCOUNT, SECURE_ANYONE_ACCOUNT);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_CreateFile");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "pMeta");
	FILE_LOG_HEX(file_log_name,(BYTE *)pMeta, sizeof(OPT_ST_USB_META));

	if(ulRet)
	{
		goto err;
	}

	ulRet = SKF_WriteFile(hAppSKF,DEFAULT_FILE_NAME,0,(BYTE *)pMeta, sizeof(OPT_ST_USB_META));
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_WriteFile");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if(ulRet)
	{
		goto err;
	}
err:

	if (hAppSKF)
	{
		SKF_CloseApplication(hAppSKF);
	}
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if (hDevSKF)
	{
		SKF_DisConnectDev(hDevSKF);
	}
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);

	return ulRet;
}
// 生成密钥对
unsigned int CAPI_KEY_GenKeyPair(char * pszKeyOn, int ulKeyTarget,char * pszPIN, unsigned int * pulRetry)
{
	unsigned int ulRet = 0;
	int ulKeyCount = 0;

	char szDevNameLists[BUFFER_LEN_1K] = {0};
	char szAppNameLists[BUFFER_LEN_1K] = {0};
	char szConNameLists[BUFFER_LEN_1K];

	ULONG ulDevNameLists = BUFFER_LEN_1K;
	ULONG ulAppNameLists = BUFFER_LEN_1K;
	ULONG ulConNameLists = BUFFER_LEN_1K;

	HANDLE hDevSKF = NULL;
	HANDLE hConSKF = NULL;
	HANDLE hAppSKF = NULL;

	ECCPUBLICKEYBLOB pubkeyBlob = {0};
	// 枚举设备
	ulRet = SKF_EnumDev(TRUE,szDevNameLists,&ulDevNameLists);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_EnumDev");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "ulDevNameLists");
	FILE_LOG_NUMBER(file_log_name,(long)ulDevNameLists);

	if(ulRet)
	{
		goto err;
	}

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "szDevNameLists");
	FILE_LOG_STRING(file_log_name,szDevNameLists);

	CAPI_GetMulStringCount(szDevNameLists, &ulKeyCount);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_EnumDev");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "ulDevNameLists");
	FILE_LOG_NUMBER(file_log_name,(long)ulDevNameLists);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "szDevNameLists");
	FILE_LOG_STRING(file_log_name,szDevNameLists);

	if (0 == ulKeyCount)
	{
		ulRet = OPE_ERR_DEV_NUMBER_ZERO;  // 未插入设备
		goto err;
	}

	if (OPE_USB_TARGET_SELF == ulKeyTarget)
	{
		if (1 != ulKeyCount)
		{
			ulRet = OPE_ERR_DEV_NUMBER_ERR;  // 设备个数不正确
			goto err;
		}

		strcpy(pszKeyOn,szDevNameLists);
	}
	else
	{
		//初始化审计员|操作员
		if (2 != ulKeyCount)
		{
			ulRet = OPE_ERR_DEV_NUMBER_ERR;  // 设备个数不正确
			goto err;
		}
	}

	// 打开设备
	ulRet = CAPI_KEY_ConnectDev(szDevNameLists,pszKeyOn,ulKeyTarget,&hDevSKF);
	if(ulRet)
	{
		goto err;
	}


	ulRet = SKF_EnumApplication(hDevSKF,szAppNameLists, &ulAppNameLists);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_EnumApplication");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if (ulAppNameLists < 2)
	{
		ulRet = OPE_ERR_OPEN_APPLICATION;
		goto err;
	}
	else
	{
		ulRet = SKF_OpenApplication(hDevSKF, szAppNameLists,&hAppSKF);
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_OpenApplication");
		FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	}

	ulRet = SKF_VerifyPIN(hAppSKF, 1, pszPIN,(ULONG *)pulRetry);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_VerifyPIN");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if(ulRet)
	{
		goto err;
	}

	ulRet = SKF_EnumContainer(hAppSKF,szConNameLists,&ulConNameLists);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_EnumContainer");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if(ulRet)
	{
		goto err;
	}

	if (NULL == CAPI_KEY_GetSubStringPtr(szConNameLists,DEFAULT_CONTAINER_SM2))
	{
		ulRet = SKF_CreateContainer(hAppSKF, DEFAULT_CONTAINER_SM2, &hConSKF);
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_CreateContainer");
		FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	}
	else
	{
		ulRet = SKF_OpenContainer(hAppSKF, DEFAULT_CONTAINER_SM2, &hConSKF);
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_OpenContainer");
		FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	}

	if(ulRet)
	{
		goto err;
	}
	// 生成签名公钥
	ulRet = SKF_GenECCKeyPair(hConSKF, SGD_SM2_1,&pubkeyBlob);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_GenECCKeyPair");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if(ulRet)
	{
		goto err;
	}

	// 拷贝签名公钥

err:
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_GenECCKeyPair");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if (hConSKF)
	{
		SKF_CloseContainer(hConSKF);
	}
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_GenECCKeyPair");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if (hAppSKF)
	{
		SKF_CloseApplication(hAppSKF);
	}
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_GenECCKeyPair");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if (hDevSKF)
	{
		SKF_DisConnectDev(hDevSKF);
	}
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_GenECCKeyPair");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);

	return ulRet;
}
// 导出公钥
unsigned int CAPI_KEY_ExportPK(char * pszKeyOn,int ulKeyTarget,unsigned int bIsSign, unsigned char * pbPK)
{
	unsigned int ulRet = 0;
	int ulKeyCount = 0;

	char szDevNameLists[BUFFER_LEN_1K] = {0};
	char szAppNameLists[BUFFER_LEN_1K] = {0};
	char szConNameLists[BUFFER_LEN_1K];

	ULONG ulDevNameLists = BUFFER_LEN_1K;
	ULONG ulAppNameLists = BUFFER_LEN_1K;
	ULONG ulConNameLists = BUFFER_LEN_1K;

	HANDLE hDevSKF = NULL;
	HANDLE hConSKF = NULL;
	HANDLE hAppSKF = NULL;

	ECCPUBLICKEYBLOB pubkeyBlob = {0};

	ULONG ulPubkeyBlobLen = sizeof(ECCPUBLICKEYBLOB);

	// 枚举设备
	ulRet = SKF_EnumDev(TRUE,szDevNameLists,&ulDevNameLists);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_EnumDev");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "ulDevNameLists");
	FILE_LOG_NUMBER(file_log_name,(long)ulDevNameLists);

	if(ulRet)
	{
		goto err;
	}

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "szDevNameLists");
	FILE_LOG_STRING(file_log_name,szDevNameLists);

	CAPI_GetMulStringCount(szDevNameLists, &ulKeyCount);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_EnumDev");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "ulDevNameLists");
	FILE_LOG_NUMBER(file_log_name,(long)ulDevNameLists);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "szDevNameLists");
	FILE_LOG_STRING(file_log_name,szDevNameLists);

	if (0 == ulKeyCount)
	{
		ulRet = OPE_ERR_DEV_NUMBER_ZERO;  // 未插入设备
		goto err;
	}

	if (OPE_USB_TARGET_SELF == ulKeyTarget)
	{
		if (1 != ulKeyCount)
		{
			ulRet = OPE_ERR_DEV_NUMBER_ERR;  // 设备个数不正确
			goto err;
		}

		strcpy(pszKeyOn,szDevNameLists);
	}
	else
	{
		//初始化审计员|操作员
		if (2 != ulKeyCount)
		{
			ulRet = OPE_ERR_DEV_NUMBER_ERR;  // 设备个数不正确
			goto err;
		}
	}

	// 打开设备
	ulRet = CAPI_KEY_ConnectDev(szDevNameLists,pszKeyOn,ulKeyTarget,&hDevSKF);
	if(ulRet)
	{
		goto err;
	}

	ulRet = SKF_EnumApplication(hDevSKF,szAppNameLists, &ulAppNameLists);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_EnumApplication");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if (ulAppNameLists < 2)
	{
		ulRet = OPE_ERR_OPEN_APPLICATION;
	}
	else
	{
		ulRet = SKF_OpenApplication(hDevSKF, szAppNameLists,&hAppSKF);
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_OpenApplication");
		FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	}

	ulRet = SKF_EnumContainer(hAppSKF,szConNameLists,&ulConNameLists);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_EnumContainer");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if(ulRet)
	{
		goto err;
	}

	if (NULL == CAPI_KEY_GetSubStringPtr(szConNameLists,DEFAULT_CONTAINER_SM2))
	{
		ulRet = SKF_CreateContainer(hAppSKF, DEFAULT_CONTAINER_SM2, &hConSKF);
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_CreateContainer");
		FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	}
	else
	{
		ulRet = SKF_OpenContainer(hAppSKF, DEFAULT_CONTAINER_SM2, &hConSKF);
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_OpenContainer");
		FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	}

	if(ulRet)
	{
		goto err;
	}
	// 导出签名公钥
	ulRet = SKF_ExportPublicKey(hConSKF, bIsSign,(BYTE *)&pubkeyBlob, &ulPubkeyBlobLen);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_ExportPublicKey");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if(ulRet)
	{
		goto err;
	}

	// 拷贝签名公钥
	memcpy(pbPK, pubkeyBlob.XCoordinate + SM2_BYTES_LEN, SM2_BYTES_LEN);
	memcpy(pbPK+SM2_BYTES_LEN, pubkeyBlob.YCoordinate + SM2_BYTES_LEN, SM2_BYTES_LEN);

err:
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "FREE");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if (hConSKF)
	{
		SKF_CloseContainer(hConSKF);
	}
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "FREE");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if (hAppSKF)
	{
		SKF_CloseApplication(hAppSKF);
	}
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "FREE");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if (hDevSKF)
	{
		SKF_DisConnectDev(hDevSKF);
	}
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, " ");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);

	return ulRet;
}
// 获取Key类型
unsigned int CAPI_KEY_GetMeta(char * pszKeyOn,int ulKeyTarget, OPT_ST_USB_META * pMeta)
{
	unsigned int ulRet = 0;

	char szDevNameLists[BUFFER_LEN_1K] = {0};
	char szAppNameLists[BUFFER_LEN_1K] = {0};

	HANDLE hDevSKF = NULL;
	HANDLE hAppSKF = NULL;

	ULONG ulDevNameLists = BUFFER_LEN_1K;
	ULONG ulAppNameLists  = BUFFER_LEN_1K;
	ULONG ulReadLen;

	int ulKeyCount = 0;


	ulRet = SKF_EnumDev(TRUE,szDevNameLists,&ulDevNameLists);

	if(ulRet)
	{
		goto err;
	}

	CAPI_GetMulStringCount(szDevNameLists, &ulKeyCount);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_EnumDev");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "ulDevNameLists");
	FILE_LOG_NUMBER(file_log_name,(long)ulDevNameLists);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "szDevNameLists");
	FILE_LOG_STRING(file_log_name,szDevNameLists);

	if (0 == ulKeyCount)
	{
		ulRet = OPE_ERR_DEV_NUMBER_ZERO;  // 未插入设备
		goto err;
	}

	if (OPE_USB_TARGET_SELF == ulKeyTarget)
	{
		if (1 != ulKeyCount)
		{
			ulRet = OPE_ERR_DEV_NUMBER_ERR;  // 设备个数不正确
			goto err;
		}

		strcpy(pszKeyOn,szDevNameLists);
	}
	else
	{
		//初始化审计员|操作员
		if (2 != ulKeyCount)
		{
			ulRet = OPE_ERR_DEV_NUMBER_ERR;  // 设备个数不正确
			goto err;
		}
	}

	// 打开设备
	ulRet = CAPI_KEY_ConnectDev(szDevNameLists,pszKeyOn,ulKeyTarget,&hDevSKF);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_ConnectDev");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	
	if(ulRet)
	{
		goto err;
	}



	ulRet = SKF_EnumApplication(hDevSKF,szAppNameLists, &ulAppNameLists);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_EnumApplication");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if (ulAppNameLists < 2)
	{
		ulRet = OPE_ERR_OPEN_APPLICATION;
		goto err;
	}
	else
	{
		ulRet = SKF_OpenApplication(hDevSKF, szAppNameLists,&hAppSKF);
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_OpenApplication");
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, szAppNameLists);
		FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	}

	if(ulRet)
	{
		goto err;
	}

	//ulRet = SKF_VerifyPIN(hAppSKF, 1, (thisClass->m_szPIN),&(thisClass->m_ulRetry));
	//FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_VerifyPIN");
	//FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	//if(ulRet)
	//{
	//	goto err;
	//}

	ulReadLen= sizeof(OPT_ST_USB_META);

	ulRet = SKF_ReadFile(hAppSKF,DEFAULT_FILE_NAME,0,sizeof(OPT_ST_USB_META),(BYTE *)pMeta, &ulReadLen);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "pMeta");
	FILE_LOG_HEX(file_log_name,(BYTE *)pMeta, sizeof(OPT_ST_USB_META));

	if(ulRet)
	{
		goto err;
	}

err:

	if (hAppSKF)
	{
		SKF_CloseApplication(hAppSKF);
	}
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if (hDevSKF)
	{
		SKF_DisConnectDev(hDevSKF);
	}
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);

	return ulRet;
}


unsigned int CAPI_KEY_CheckOnOff(char * pszKeyOn,int ulKeyTarget, OPT_ST_USB_META * pstMeta)
{
	unsigned int ulRet = 0;

	char * ptrDevName = NULL;

	OPT_ST_USB_META stMeta;

	char szDevNameLists[BUFFER_LEN_1K] = {0};
	char szAppNameLists[BUFFER_LEN_1K] = {0};

	HANDLE hDevSKF = NULL;
	HANDLE hAppSKF = NULL;

	ULONG ulDevNameLists = BUFFER_LEN_1K;
	ULONG ulAppNameLists  = BUFFER_LEN_1K;
	ULONG ulReadLen;

	int ulKeyCount = 0;


	ulRet = SKF_EnumDev(TRUE,szDevNameLists,&ulDevNameLists);

	if(ulRet)
	{
		goto err;
	}

	CAPI_GetMulStringCount(szDevNameLists, &ulKeyCount);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_EnumDev");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "ulDevNameLists");
	FILE_LOG_NUMBER(file_log_name,(long)ulDevNameLists);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "szDevNameLists");
	FILE_LOG_STRING(file_log_name,szDevNameLists);

	if (0 == strlen(pszKeyOn) || 1 >  ulKeyCount )
	{
		ulRet = OPE_ERR_DEV_NUMBER_ERR;  // 设备个数不正确
		goto err;
	}

	for (ptrDevName = szDevNameLists; *ptrDevName;)
	{

		hDevSKF = NULL;
		hAppSKF = NULL;

		ulAppNameLists = BUFFER_LEN_1K;
		ulReadLen = sizeof(OPT_ST_USB_META);

		// 打开设备
		ulRet = CAPI_KEY_ConnectDev(ptrDevName,ptrDevName,ulKeyTarget,&hDevSKF);
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_ConnectDev");
		FILE_LOG_NUMBER(file_log_name,(long)ulRet);

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "ptrDevName");
		FILE_LOG_STRING(file_log_name,ptrDevName);

		if(ulRet)
		{
			goto err_continue;
		}



		ulRet = SKF_EnumApplication(hDevSKF,szAppNameLists, &ulAppNameLists);

		if(ulRet)
		{
			goto err_continue;
		}

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_EnumApplication");
		FILE_LOG_NUMBER(file_log_name,(long)ulRet);
		if (ulAppNameLists < 2)
		{
			ulRet = OPE_ERR_OPEN_APPLICATION;
			goto err_continue;
		}
		else
		{
			ulRet = SKF_OpenApplication(hDevSKF, szAppNameLists,&hAppSKF);
			FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_OpenApplication");
			FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, szAppNameLists);
			FILE_LOG_NUMBER(file_log_name,(long)ulRet);
		}

		if(ulRet)
		{
			goto err_continue;
		}

		//ulRet = SKF_VerifyPIN(hAppSKF, 1, (thisClass->m_szPIN),&(thisClass->m_ulRetry));
		//FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_VerifyPIN");
		//FILE_LOG_NUMBER(file_log_name,(long)ulRet);
		//if(ulRet)
		//{
		//	goto err;
		//}

		ulRet = SKF_ReadFile(hAppSKF,DEFAULT_FILE_NAME,0,sizeof(OPT_ST_USB_META),(BYTE *)&stMeta, &ulReadLen);

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "pstMeta");
		FILE_LOG_HEX(file_log_name,(BYTE *)&stMeta, sizeof(OPT_ST_USB_META));

		if(ulRet)
		{
			goto err_continue;
		}

		if (0 != memcmp(&stMeta,pstMeta, sizeof(OPT_ST_USB_META)))
		{
			ulRet = OPE_ERR_DEV_NUMBER_ZERO;  // 设备个数不正确
		}
		else // SUCCESS
		{
			if (hAppSKF)
			{
				SKF_CloseApplication(hAppSKF);
			}
			FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
			FILE_LOG_NUMBER(file_log_name,(long)ulRet);

			if (hDevSKF)
			{
				SKF_DisConnectDev(hDevSKF);
			}
			FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
			FILE_LOG_NUMBER(file_log_name,(long)ulRet);

			strcpy(pszKeyOn,ptrDevName); // COPY

			break;
		}

err_continue:
		if (hAppSKF)
		{
			SKF_CloseApplication(hAppSKF);
		}
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
		FILE_LOG_NUMBER(file_log_name,(long)ulRet);

		if (hDevSKF)
		{
			SKF_DisConnectDev(hDevSKF);
		}
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
		FILE_LOG_NUMBER(file_log_name,(long)ulRet);

		ptrDevName += strlen(ptrDevName);
		ptrDevName += 1;
	}

err:

	return ulRet;
}

unsigned int CAPI_KEY_SecureState(char * pszKeyOn,int ulKeyTarget, OPT_ST_USB_META * pstMeta)
{
#if defined(WIN32) || defined(WINDOWS)
	unsigned int ulRet = -1;

	char * ptrDevName = NULL;

	OPT_ST_USB_META stMeta;

	char szDevNameLists[BUFFER_LEN_1K] = {0};
	char szAppNameLists[BUFFER_LEN_1K] = {0};

	HANDLE hDevSKF = NULL;
	HANDLE hAppSKF = NULL;

	ULONG ulDevNameLists = BUFFER_LEN_1K;
	ULONG ulAppNameLists  = BUFFER_LEN_1K;
	ULONG ulReadLen;

	int ulKeyCount = 0;

	ulRet = SKF_EnumDev(TRUE,szDevNameLists,&ulDevNameLists);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);

	if(ulRet)
	{
		goto err;
	}

	CAPI_GetMulStringCount(szDevNameLists, &ulKeyCount);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_EnumDev");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "ulDevNameLists");
	FILE_LOG_NUMBER(file_log_name,(long)ulDevNameLists);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "szDevNameLists");
	FILE_LOG_STRING(file_log_name,szDevNameLists);

	if (0 == strlen(pszKeyOn) || 1 >  ulKeyCount )
	{
		ulRet = OPE_ERR_DEV_NUMBER_ERR;  // 设备个数不正确
		goto err;
	}

	for (ptrDevName = szDevNameLists; *ptrDevName;)
	{

		hDevSKF = NULL;
		hAppSKF = NULL;

		ulAppNameLists = BUFFER_LEN_1K;
		ulReadLen = sizeof(OPT_ST_USB_META);

		// 打开设备
		ulRet = CAPI_KEY_ConnectDev(ptrDevName,ptrDevName,ulKeyTarget,&hDevSKF);
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_ConnectDev");
		FILE_LOG_NUMBER(file_log_name,(long)ulRet);

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "ptrDevName");
		FILE_LOG_STRING(file_log_name,ptrDevName);

		if(ulRet)
		{
			goto err_continue;
		}

		ulRet = SKF_EnumApplication(hDevSKF,szAppNameLists, &ulAppNameLists);

		if(ulRet)
		{
			goto err_continue;
		}

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_EnumApplication");
		FILE_LOG_NUMBER(file_log_name,(long)ulRet);
		if (ulAppNameLists < 2)
		{
			ulRet = OPE_ERR_OPEN_APPLICATION;
			goto err_continue;
		}
		else
		{
			ulRet = SKF_OpenApplication(hDevSKF, szAppNameLists,&hAppSKF);
			FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_OpenApplication");
			FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, szAppNameLists);
			FILE_LOG_NUMBER(file_log_name,(long)ulRet);
		}

		if(ulRet)
		{
			goto err_continue;
		}

		//ulRet = SKF_VerifyPIN(hAppSKF, 1, (thisClass->m_szPIN),&(thisClass->m_ulRetry));
		//FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_VerifyPIN");
		//FILE_LOG_NUMBER(file_log_name,(long)ulRet);
		//if(ulRet)
		//{
		//	goto err;
		//}

		ulRet = SKF_ReadFile(hAppSKF,DEFAULT_FILE_NAME,0,sizeof(OPT_ST_USB_META),(BYTE *)&stMeta, &ulReadLen);

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "pstMeta");
		FILE_LOG_HEX(file_log_name,(BYTE *)&stMeta, sizeof(OPT_ST_USB_META));

		if(ulRet)
		{
			goto err_continue;
		}

		if (0 != memcmp(&stMeta,pstMeta, sizeof(OPT_ST_USB_META)))
		{
			ulRet = OPE_ERR_DEV_NUMBER_ZERO;  // 设备个数不正确
		}
		else // SUCCESS
		{
			ULONG ulSecureState = 0;

			ulRet = SKF_GetSecureState(hAppSKF,&ulSecureState);
			FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_GetSecureState");
			FILE_LOG_NUMBER(file_log_name,(long)ulRet);

			if(ulRet || 1 != ulSecureState)
			{
				ulRet = -1;
			}
			else
			{
				ulRet = 0;
			}


			if (hAppSKF)
			{
				SKF_CloseApplication(hAppSKF);
			}
			FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
			FILE_LOG_NUMBER(file_log_name,(long)ulRet);

			if (hDevSKF)
			{
				SKF_DisConnectDev(hDevSKF);
			}
			FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
			FILE_LOG_NUMBER(file_log_name,(long)ulRet);

			strcpy(pszKeyOn,ptrDevName); // COPY

			break;
		}

err_continue:
		if (hAppSKF)
		{
			SKF_CloseApplication(hAppSKF);
		}
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
		FILE_LOG_NUMBER(file_log_name,(long)ulRet);

		if (hDevSKF)
		{
			SKF_DisConnectDev(hDevSKF);
		}
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
		FILE_LOG_NUMBER(file_log_name,(long)ulRet);

		ptrDevName += strlen(ptrDevName);
		ptrDevName += 1;
	}

err:

	return ulRet;
#else
	return 0;
#endif
	
}


unsigned int CAPI_KEY_UnlockWeb(char * pszKeyOn,int ulKeyTarget, OPT_ST_USB_META * pstMeta,char * pszPIN,unsigned int * pulRetry)
{
	unsigned int ulRet = 0;

	char * ptrDevName = NULL;

	OPT_ST_USB_META stMeta;

	char szDevNameLists[BUFFER_LEN_1K] = {0};
	char szAppNameLists[BUFFER_LEN_1K] = {0};

	HANDLE hDevSKF = NULL;
	HANDLE hAppSKF = NULL;

	ULONG ulDevNameLists = BUFFER_LEN_1K;
	ULONG ulAppNameLists  = BUFFER_LEN_1K;
	ULONG ulReadLen;

	int ulKeyCount = 0;

	ulRet = SKF_EnumDev(TRUE,szDevNameLists,&ulDevNameLists);

	if(ulRet)
	{
		goto err;
	}

	CAPI_GetMulStringCount(szDevNameLists, &ulKeyCount);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_EnumDev");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "ulDevNameLists");
	FILE_LOG_NUMBER(file_log_name,(long)ulDevNameLists);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "szDevNameLists");
	FILE_LOG_STRING(file_log_name,szDevNameLists);

	if (0 == strlen(pszKeyOn) || 1 >  ulKeyCount )
	{
		ulRet = OPE_ERR_DEV_NUMBER_ERR;  // 设备个数不正确
		goto err;
	}

	for (ptrDevName = szDevNameLists; *ptrDevName;)
	{

		hDevSKF = NULL;
		hAppSKF = NULL;

		ulAppNameLists = BUFFER_LEN_1K;

		ulReadLen = sizeof(OPT_ST_USB_META);

		// 打开设备
		ulRet = CAPI_KEY_ConnectDev(ptrDevName,ptrDevName,ulKeyTarget,&hDevSKF);
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_ConnectDev");
		FILE_LOG_NUMBER(file_log_name,(long)ulRet);

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "ptrDevName");
		FILE_LOG_STRING(file_log_name,ptrDevName);

		if(ulRet)
		{
			goto err_continue;
		}



		ulRet = SKF_EnumApplication(hDevSKF,szAppNameLists, &ulAppNameLists);

		if(ulRet)
		{
			goto err_continue;
		}

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_EnumApplication");
		FILE_LOG_NUMBER(file_log_name,(long)ulRet);
		if (ulAppNameLists < 2)
		{
			ulRet = OPE_ERR_OPEN_APPLICATION;
			goto err_continue;
		}
		else
		{
			ulRet = SKF_OpenApplication(hDevSKF, szAppNameLists,&hAppSKF);
			FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_OpenApplication");
			FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, szAppNameLists);
			FILE_LOG_NUMBER(file_log_name,(long)ulRet);
		}

		if(ulRet)
		{
			goto err_continue;
		}

		ulRet = SKF_ReadFile(hAppSKF,DEFAULT_FILE_NAME,0,sizeof(OPT_ST_USB_META),(BYTE *)&stMeta, &ulReadLen);

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "pstMeta");
		FILE_LOG_HEX(file_log_name,(BYTE *)&stMeta, sizeof(OPT_ST_USB_META));

		if(ulRet)
		{
			goto err_continue;
		}

		if (0 != memcmp(&stMeta,pstMeta, sizeof(OPT_ST_USB_META)))
		{
			ulRet = OPE_ERR_DEV_NUMBER_ZERO;  // 设备个数不正确
		}
		else // SUCCESS
		{
			ulRet = SKF_VerifyPIN(hAppSKF, 1, pszPIN,(ULONG *)pulRetry);
			FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_VerifyPIN");
			FILE_LOG_NUMBER(file_log_name,(long)ulRet);
			if(ulRet)
			{
				goto err_continue;
			}

			if (hAppSKF)
			{
				SKF_CloseApplication(hAppSKF);
			}
			FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
			FILE_LOG_NUMBER(file_log_name,(long)ulRet);

			if (hDevSKF)
			{
				SKF_DisConnectDev(hDevSKF);
			}
			FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
			FILE_LOG_NUMBER(file_log_name,(long)ulRet);

			strcpy(pszKeyOn,ptrDevName); // COPY

			break;
		}

err_continue:
		if (hAppSKF)
		{
			SKF_CloseApplication(hAppSKF);
		}
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
		FILE_LOG_NUMBER(file_log_name,(long)ulRet);

		if (hDevSKF)
		{
			SKF_DisConnectDev(hDevSKF);
		}
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
		FILE_LOG_NUMBER(file_log_name,(long)ulRet);

		ptrDevName += strlen(ptrDevName);
		ptrDevName += 1;
	}

err:

	return ulRet;
}


unsigned int CAPI_KEY_ImportKeyPair(char * pszKeyOn,int ulKeyTarget, unsigned int bIsSign, unsigned char * pbKeyPair, char * pszPIN, unsigned int * pulRetry)
{
	char szDevNameLists[BUFFER_LEN_1K] = {0};
	char szAppNameLists[BUFFER_LEN_1K] = {0};
	char szConNameLists[BUFFER_LEN_1K];

	ULONG ulDevNameLists = BUFFER_LEN_1K;
	ULONG ulAppNameLists = BUFFER_LEN_1K;
	ULONG ulConNameLists = BUFFER_LEN_1K;

	HANDLE hDevSKF = NULL;
	HANDLE hConSKF = NULL;
	HANDLE hAppSKF = NULL;

	unsigned int ulRet = 0;
	int ulKeyCount = 0;

	// 枚举设备
	ulRet = SKF_EnumDev(TRUE,szDevNameLists,&ulDevNameLists);

	if(ulRet)
	{
		goto err;
	}

	CAPI_GetMulStringCount(szDevNameLists, &ulKeyCount);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_EnumDev");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "ulDevNameLists");
	FILE_LOG_NUMBER(file_log_name,(long)ulDevNameLists);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "szDevNameLists");
	FILE_LOG_STRING(file_log_name,szDevNameLists);

	if (0 == ulKeyCount)
	{
		ulRet = OPE_ERR_DEV_NUMBER_ZERO;  // 未插入设备
		goto err;
	}

	if (OPE_USB_TARGET_SELF == ulKeyTarget)
	{
		if (1 != ulKeyCount)
		{
			ulRet = OPE_ERR_DEV_NUMBER_ERR;  // 设备个数不正确
			goto err;
		}

		strcpy(pszKeyOn,szDevNameLists);
	}
	else
	{
		//初始化审计员|操作员
		if (2 != ulKeyCount)
		{
			ulRet = OPE_ERR_DEV_NUMBER_ERR;  // 设备个数不正确
			goto err;
		}
	}

	// 打开设备
	ulRet = CAPI_KEY_ConnectDev(szDevNameLists,pszKeyOn,ulKeyTarget,&hDevSKF);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_ConnectDev");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if(ulRet)
	{
		goto err;
	}

	ulRet = SKF_EnumApplication(hDevSKF,szAppNameLists, &ulAppNameLists);

	// 设备认证或者打开一个应用
	if (ulAppNameLists < 2)
	{
		ulRet = OPE_ERR_OPEN_APPLICATION;
	}
	else
	{
		ulRet = SKF_OpenApplication(hDevSKF, szAppNameLists,&hAppSKF);
	}

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "hAppSKFN");
	FILE_LOG_NUMBER(file_log_name,(long)hAppSKF);

	// 验证密码
	ulRet = SKF_VerifyPIN(hAppSKF, 1, pszPIN,(ULONG *)pulRetry);
	if(ulRet)
	{
		goto err;
	}

	// 枚举容器
	ulRet = SKF_EnumContainer(hAppSKF,szConNameLists,&ulConNameLists);
	if(ulRet)
	{
		goto err;
	}
	// 创建或打开容器
	if (NULL == CAPI_KEY_GetSubStringPtr(szConNameLists,DEFAULT_CONTAINER_SM2))
	{
		ulRet = SKF_CreateContainer(hAppSKF, DEFAULT_CONTAINER_SM2, &hConSKF);
	}
	else
	{
		ulRet = SKF_OpenContainer(hAppSKF, DEFAULT_CONTAINER_SM2, &hConSKF);
	}

	if(ulRet)
	{
		goto err;
	}
	// 导入数字信封格式的交换密钥对
	ulRet = SKF_ImportECCKeyPair(hConSKF, (PENVELOPEDKEYBLOB)pbKeyPair);
	if(ulRet)
	{
		goto err;
	}

err:
	if (hConSKF)
	{
		SKF_CloseContainer(hConSKF);
	}

	if (hAppSKF)
	{
		SKF_CloseApplication(hAppSKF);
	}

	if (hDevSKF)
	{
		SKF_DisConnectDev(hDevSKF);
	}

	return ulRet;
}

unsigned int CAPI_KEY_ImportCert(char * pszKeyOn,int ulKeyTarget, unsigned int bIsSign,unsigned char * pbCert,unsigned int ulCertLen, char * pszPIN, unsigned int * pulRetry)
{
	char szDevNameLists[BUFFER_LEN_1K] = {0};
	char szAppNameLists[BUFFER_LEN_1K] = {0};
	char szConNameLists[BUFFER_LEN_1K];

	ULONG ulDevNameLists = BUFFER_LEN_1K;
	ULONG ulAppNameLists = BUFFER_LEN_1K;
	ULONG ulConNameLists = BUFFER_LEN_1K;

	HANDLE hDevSKF = NULL;
	HANDLE hConSKF = NULL;
	HANDLE hAppSKF = NULL;

	unsigned int ulRet = 0;
	int ulKeyCount = 0;

	// 枚举设备
	ulRet = SKF_EnumDev(TRUE,szDevNameLists,&ulDevNameLists);

	if(ulRet)
	{
		goto err;
	}

	CAPI_GetMulStringCount(szDevNameLists, &ulKeyCount);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_EnumDev");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "ulDevNameLists");
	FILE_LOG_NUMBER(file_log_name,(long)ulDevNameLists);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "szDevNameLists");
	FILE_LOG_STRING(file_log_name,szDevNameLists);

	if (0 == ulKeyCount)
	{
		ulRet = OPE_ERR_DEV_NUMBER_ZERO;  // 未插入设备
		goto err;
	}

	if (OPE_USB_TARGET_SELF == ulKeyTarget)
	{
		if (1 != ulKeyCount)
		{
			ulRet = OPE_ERR_DEV_NUMBER_ERR;  // 设备个数不正确
			goto err;
		}

		strcpy(pszKeyOn,szDevNameLists);
	}
	else
	{
		//初始化审计员|操作员
		if (2 != ulKeyCount)
		{
			ulRet = OPE_ERR_DEV_NUMBER_ERR;  // 设备个数不正确
			goto err;
		}
	}

	// 打开设备
	ulRet = CAPI_KEY_ConnectDev(szDevNameLists,pszKeyOn,ulKeyTarget,&hDevSKF);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_ConnectDev");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if(ulRet)
	{
		goto err;
	}

	ulRet = SKF_EnumApplication(hDevSKF,szAppNameLists, &ulAppNameLists);

	// 设备认证或者打开一个应用
	if (ulAppNameLists < 2)
	{
		ulRet = OPE_ERR_OPEN_APPLICATION;
	}
	else
	{
		ulRet = SKF_OpenApplication(hDevSKF, szAppNameLists,&hAppSKF);
	}

	// 验证密码
	ulRet = SKF_VerifyPIN(hAppSKF, 1, pszPIN,(ULONG *)pulRetry);
	if(ulRet)
	{
		goto err;
	}

	// 枚举容器
	ulRet = SKF_EnumContainer(hAppSKF,szConNameLists,&ulConNameLists);
	if(ulRet)
	{
		goto err;
	}
	// 创建或打开容器
	if (NULL == CAPI_KEY_GetSubStringPtr(szConNameLists,DEFAULT_CONTAINER_SM2))
	{
		ulRet = SKF_CreateContainer(hAppSKF, DEFAULT_CONTAINER_SM2, &hConSKF);
	}
	else
	{
		ulRet = SKF_OpenContainer(hAppSKF, DEFAULT_CONTAINER_SM2, &hConSKF);
	}

	if(ulRet)
	{
		goto err;
	}
	// 导入证书
	ulRet = SKF_ImportCertificate(hConSKF, bIsSign,pbCert,ulCertLen);
	if(ulRet)
	{
		goto err;
	}
err:
	if (hConSKF)
	{
		SKF_CloseContainer(hConSKF);
	}

	if (hAppSKF)
	{
		SKF_CloseApplication(hAppSKF);
	}

	if (hDevSKF)
	{
		SKF_DisConnectDev(hDevSKF);
	}

	return ulRet;
}



// 删除所有应用
unsigned int CAPI_KEY_ClearApp(/*IN OUT*/char * pszKeyOn, int ulKeyTarget)
{
	unsigned long ulRet;

	char szDevNameLists[BUFFER_LEN_1K] = {0};
	char szAppNameLists[BUFFER_LEN_1K] = {0};

	HANDLE hDevSKF = NULL;
	HANDLE hAppSKF = NULL;

	ULONG ulDevNameLists = BUFFER_LEN_1K;
	ULONG ulAppNameLists = BUFFER_LEN_1K;

	int ulKeyCount = 0;


	ulRet = SKF_EnumDev(TRUE,szDevNameLists,&ulDevNameLists);

	if(ulRet)
	{
		goto err;
	}

	CAPI_GetMulStringCount(szDevNameLists, &ulKeyCount);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_EnumDev");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "ulDevNameLists");
	FILE_LOG_NUMBER(file_log_name,(long)ulDevNameLists);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "szDevNameLists");
	FILE_LOG_STRING(file_log_name,szDevNameLists);

	if (0 == ulKeyCount)
	{
		ulRet = OPE_ERR_DEV_NUMBER_ZERO;  // 未插入设备
		goto err;
	}

	if (OPE_USB_TARGET_SELF == ulKeyTarget)
	{
		if (1 != ulKeyCount)
		{
			ulRet = OPE_ERR_DEV_NUMBER_ERR;  // 设备个数不正确
			goto err;
		}

		strcpy(pszKeyOn,szDevNameLists);
	}
	else
	{
		if (2 != ulKeyCount)
		{
			ulRet = OPE_ERR_DEV_NUMBER_ERR;  // 设备个数不正确
			goto err;
		}
	}

	// 打开设备
	ulRet = CAPI_KEY_ConnectDev(szDevNameLists,pszKeyOn,ulKeyTarget,&hDevSKF);
	if(ulRet)
	{
		goto err;
	}

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_ConnectDev");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);

	ulRet = CAPI_KEY_DevAuth(hDevSKF);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "CAPI_KEY_DevAuth");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if(ulRet)
	{
		goto err;
	}

	// 枚举应用
	ulRet = SKF_EnumApplication(hDevSKF,szAppNameLists, &ulAppNameLists);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_EnumApplication");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);

	// 删除所有应用
	{
		char * ptr = szAppNameLists;

		for (ptr = szAppNameLists;*ptr;)
		{
			ulRet = SKF_DeleteApplication(hDevSKF, ptr);//删除应用
			FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_DeleteApplication");
			FILE_LOG_NUMBER(file_log_name,(long)ulRet);
			if(ulRet)
			{
				goto err;
			}

			// 移动到下一个应用
			ptr += strlen(ptr);
			ptr++;

		}
	}
	

err:

	if (hAppSKF)
	{
		SKF_CloseApplication(hAppSKF);
	}

	if (hDevSKF)
	{
		SKF_DisConnectDev(hDevSKF);
	}

	return ulRet;
}


unsigned int CAPI_KEY_GetInfo(/*IN OUT*/char * pszKeyOn, int ulKeyTarget,DEVINFO * pInfo)
{
	unsigned long ulRet;

	char szDevNameLists[BUFFER_LEN_1K] = {0};

	HANDLE hDevSKF = NULL;

	DEVINFO devInfo = {0};

	ULONG ulDevNameLists = BUFFER_LEN_1K;
	ULONG ulAppNameLists = 0;

	int ulKeyCount = 0;


	ulRet = SKF_EnumDev(TRUE,szDevNameLists,&ulDevNameLists);

	if(ulRet)
	{
		goto err;
	}

	CAPI_GetMulStringCount(szDevNameLists, &ulKeyCount);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_EnumDev");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "ulDevNameLists");
	FILE_LOG_NUMBER(file_log_name,(long)ulDevNameLists);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "szDevNameLists");
	FILE_LOG_STRING(file_log_name,szDevNameLists);

	if (0 == ulKeyCount)
	{
		ulRet = OPE_ERR_DEV_NUMBER_ZERO;  // 未插入设备
		goto err;
	}

	if (OPE_USB_TARGET_SELF == ulKeyTarget)
	{
		if (1 != ulKeyCount)
		{
			ulRet = OPE_ERR_DEV_NUMBER_ERR;  // 设备个数不正确
			goto err;
		}

		strcpy(pszKeyOn,szDevNameLists);
	}
	else
	{
		if (2 != ulKeyCount)
		{
			ulRet = OPE_ERR_DEV_NUMBER_ERR;  // 设备个数不正确
			goto err;
		}
	}

	// 打开设备
	ulRet = CAPI_KEY_ConnectDev(szDevNameLists,pszKeyOn,ulKeyTarget,&hDevSKF);
	if(ulRet)
	{
		goto err;
	}

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_ConnectDev");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);

	ulRet = CAPI_KEY_DevAuth(hDevSKF);
	if(ulRet)
	{
		goto err;
	}

	ulRet = SKF_GetDevInfo(hDevSKF,&devInfo);
	if(ulRet)
	{
		goto err;
	}

	memcpy(pInfo,&devInfo,sizeof(DEVINFO));

err:

	if (hDevSKF)
	{
		SKF_DisConnectDev(hDevSKF);
	}

	return ulRet;
}

#if defined(GM_ECC_512_SUPPORT)
// 生成密钥对512
unsigned int CAPI_KEY_ECC512GenKeyPair(char * pszKeyOn,int ulKeyTarget, unsigned int bIsSign, char * pszPIN, unsigned int * pulRetry)
{
	unsigned int ulRet = 0;
	int ulKeyCount = 0;

	char szDevNameLists[BUFFER_LEN_1K] = {0};
	char szAppNameLists[BUFFER_LEN_1K] = {0};
	char szConNameLists[BUFFER_LEN_1K];

	ULONG ulDevNameLists = BUFFER_LEN_1K;
	ULONG ulAppNameLists = BUFFER_LEN_1K;
	ULONG ulConNameLists = BUFFER_LEN_1K;

	HANDLE hDevSKF = NULL;
	HANDLE hConSKF = NULL;
	HANDLE hAppSKF = NULL;

	ECCPUBLICKEYBLOB pubkeyBlob = {0};
	// 枚举设备
	ulRet = SKF_EnumDev(TRUE,szDevNameLists,&ulDevNameLists);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_EnumDev");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "ulDevNameLists");
	FILE_LOG_NUMBER(file_log_name,(long)ulDevNameLists);

	if(ulRet)
	{
		goto err;
	}

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "szDevNameLists");
	FILE_LOG_STRING(file_log_name,szDevNameLists);

	CAPI_GetMulStringCount(szDevNameLists, &ulKeyCount);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_EnumDev");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "ulDevNameLists");
	FILE_LOG_NUMBER(file_log_name,(long)ulDevNameLists);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "szDevNameLists");
	FILE_LOG_STRING(file_log_name,szDevNameLists);

	if (0 == ulKeyCount)
	{
		ulRet = OPE_ERR_DEV_NUMBER_ZERO;  // 未插入设备
		goto err;
	}

	if (OPE_USB_TARGET_SELF == ulKeyTarget)
	{
		if (1 != ulKeyCount)
		{
			ulRet = OPE_ERR_DEV_NUMBER_ERR;  // 设备个数不正确
			goto err;
		}

		strcpy(pszKeyOn,szDevNameLists);
	}
	else
	{
		//初始化审计员|操作员
		if (2 != ulKeyCount)
		{
			ulRet = OPE_ERR_DEV_NUMBER_ERR;  // 设备个数不正确
			goto err;
		}
	}

	// 打开设备
	ulRet = CAPI_KEY_ConnectDev(szDevNameLists,pszKeyOn,ulKeyTarget,&hDevSKF);
	if(ulRet)
	{
		goto err;
	}


	ulRet = SKF_EnumApplication(hDevSKF,szAppNameLists, &ulAppNameLists);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_EnumApplication");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if (ulAppNameLists < 2)
	{
		ulRet = OPE_ERR_OPEN_APPLICATION;
		goto err;
	}
	else
	{
		ulRet = SKF_OpenApplication(hDevSKF, szAppNameLists,&hAppSKF);
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_OpenApplication");
		FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	}

	ulRet = SKF_VerifyPIN(hAppSKF, 1, pszPIN,(ULONG *)pulRetry);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_VerifyPIN");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if(ulRet)
	{
		goto err;
	}

	ulRet = SKF_EnumContainer(hAppSKF,szConNameLists,&ulConNameLists);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_EnumContainer");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if(ulRet)
	{
		goto err;
	}

	if (NULL == CAPI_KEY_GetSubStringPtr(szConNameLists,DEFAULT_CONTAINER_ECC512))
	{
		ulRet = SKF_CreateContainer(hAppSKF, DEFAULT_CONTAINER_ECC512, &hConSKF);
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_CreateContainer");
		FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	}
	else
	{
		ulRet = SKF_OpenContainer(hAppSKF, DEFAULT_CONTAINER_ECC512, &hConSKF);
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_OpenContainer");
		FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	}

	if(ulRet)
	{
		goto err;
	}
	// 生成签名公钥

	if (1 == bIsSign)
	{
		ulRet = SKF_GenECCKeyPair(hConSKF, SGD_ECC_512,&pubkeyBlob);
	}
	else if(0 == bIsSign)
	{
		ulRet = SKF_GenECCEncryptKeyPair(hConSKF, SGD_ECC_512,&pubkeyBlob);
	}

	
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_GenECCKeyPair");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if(ulRet)
	{
		goto err;
	}

	// 拷贝签名公钥

err:
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_GenECCKeyPair");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if (hConSKF)
	{
		SKF_CloseContainer(hConSKF);
	}
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_GenECCKeyPair");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if (hAppSKF)
	{
		SKF_CloseApplication(hAppSKF);
	}
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_GenECCKeyPair");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if (hDevSKF)
	{
		SKF_DisConnectDev(hDevSKF);
	}
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_GenECCKeyPair");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);

	return ulRet;
}
// 数据签名512
unsigned int CAPI_KEY_ECC512SignDigest(char * pszKeyOn,int ulKeyTarget, char * pszPIN, unsigned char *pbDigest, unsigned char * pbSigValue, unsigned int * pulRetry)
{
	unsigned int ulRet = 0;

	char szDevNameLists[BUFFER_LEN_1K] = {0};
	char szAppNameLists[BUFFER_LEN_1K] = {0};
	char szConNameLists[BUFFER_LEN_1K] = {0};

	HANDLE hDevSKF = NULL;
	HANDLE hAppSKF = NULL;
	HANDLE hConSKF = NULL;

	ULONG ulDevNameLists = BUFFER_LEN_1K;
	ULONG ulAppNameLists = BUFFER_LEN_1K;
	ULONG ulConNameLists = BUFFER_LEN_1K;

	ECCSIGNATUREBLOB stSigBlob = {0};

	int ulKeyCount = 0;

	ulRet = SKF_EnumDev(TRUE,szDevNameLists,&ulDevNameLists);

	if(ulRet)
	{
		goto err;
	}

	CAPI_GetMulStringCount(szDevNameLists, &ulKeyCount);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_EnumDev");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "ulDevNameLists");
	FILE_LOG_NUMBER(file_log_name,(long)ulDevNameLists);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "szDevNameLists");
	FILE_LOG_STRING(file_log_name,szDevNameLists);

	if (0 == ulKeyCount)
	{
		ulRet = OPE_ERR_DEV_NUMBER_ZERO;  // 未插入设备
		goto err;
	}

	if (OPE_USB_TARGET_SELF == ulKeyTarget)
	{
		if (1 != ulKeyCount)
		{
			ulRet = OPE_ERR_DEV_NUMBER_ERR;  // 设备个数不正确
			goto err;
		}

		strcpy(pszKeyOn,szDevNameLists);
	}
	else
	{
		//初始化审计员|操作员
		if (2 != ulKeyCount)
		{
			ulRet = OPE_ERR_DEV_NUMBER_ERR;  // 设备个数不正确
			goto err;
		}
	}

	// 打开设备
	ulRet = CAPI_KEY_ConnectDev(szDevNameLists,pszKeyOn,ulKeyTarget,&hDevSKF);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_ConnectDev");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if(ulRet)
	{
		goto err;
	}

	ulRet = SKF_EnumApplication(hDevSKF,szAppNameLists, &ulAppNameLists);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_EnumApplication");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if (ulAppNameLists < 2)
	{
		ulRet = OPE_ERR_OPEN_APPLICATION;
		goto err;
	}
	else
	{
		ulRet = SKF_OpenApplication(hDevSKF, szAppNameLists,&hAppSKF);
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_OpenApplication");
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, szAppNameLists);
		FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	}


	if(ulRet)
	{
		goto err;
	}


	ulRet = SKF_VerifyPIN(hAppSKF, 1, pszPIN,(ULONG *)pulRetry);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_VerifyPIN");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if(ulRet)
	{
		goto err;
	}


	// 枚举容器
	ulRet = SKF_EnumContainer(hAppSKF,szConNameLists,&ulConNameLists);
	if(ulRet)
	{
		goto err;
	}
	// 创建或打开容器
	if (NULL == CAPI_KEY_GetSubStringPtr(szConNameLists,DEFAULT_CONTAINER_ECC512))
	{
		ulRet = SKF_CreateContainer(hAppSKF, DEFAULT_CONTAINER_ECC512, &hConSKF);
	}
	else
	{
		ulRet = SKF_OpenContainer(hAppSKF, DEFAULT_CONTAINER_ECC512, &hConSKF);
	}

	if(ulRet)
	{
		goto err;
	}

	ulRet = SKF_ECCSignData(hConSKF,pbDigest,64,&stSigBlob);
	if(ulRet)
	{
		goto err;
	}

	memcpy(pbSigValue,stSigBlob.r, 64);
	memcpy(pbSigValue + 64,stSigBlob.s, 64);

err:

	if(hConSKF)
	{
		SKF_CloseContainer(hConSKF);
	}

	if (hAppSKF)
	{
		SKF_CloseApplication(hAppSKF);
	}
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if (hDevSKF)
	{
		SKF_DisConnectDev(hDevSKF);
	}
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);

	return ulRet;
}

// 导出公钥512
unsigned int CAPI_KEY_ECC512ExportPK(char * pszKeyOn,int ulKeyTarget,unsigned int bIsSign, unsigned char * pbPK)
{
	unsigned int ulRet = 0;
	int ulKeyCount = 0;

	char szDevNameLists[BUFFER_LEN_1K] = {0};
	char szAppNameLists[BUFFER_LEN_1K] = {0};
	char szConNameLists[BUFFER_LEN_1K];

	ULONG ulDevNameLists = BUFFER_LEN_1K;
	ULONG ulAppNameLists = BUFFER_LEN_1K;
	ULONG ulConNameLists = BUFFER_LEN_1K;

	HANDLE hDevSKF = NULL;
	HANDLE hConSKF = NULL;
	HANDLE hAppSKF = NULL;

	ECCPUBLICKEYBLOB pubkeyBlob = {0};

	ULONG ulPubkeyBlobLen = sizeof(ECCPUBLICKEYBLOB);

	// 枚举设备
	ulRet = SKF_EnumDev(TRUE,szDevNameLists,&ulDevNameLists);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_EnumDev");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "ulDevNameLists");
	FILE_LOG_NUMBER(file_log_name,(long)ulDevNameLists);

	if(ulRet)
	{
		goto err;
	}

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "szDevNameLists");
	FILE_LOG_STRING(file_log_name,szDevNameLists);

	CAPI_GetMulStringCount(szDevNameLists, &ulKeyCount);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_EnumDev");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "ulDevNameLists");
	FILE_LOG_NUMBER(file_log_name,(long)ulDevNameLists);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "szDevNameLists");
	FILE_LOG_STRING(file_log_name,szDevNameLists);

	if (0 == ulKeyCount)
	{
		ulRet = OPE_ERR_DEV_NUMBER_ZERO;  // 未插入设备
		goto err;
	}

	if (OPE_USB_TARGET_SELF == ulKeyTarget)
	{
		if (1 != ulKeyCount)
		{
			ulRet = OPE_ERR_DEV_NUMBER_ERR;  // 设备个数不正确
			goto err;
		}

		strcpy(pszKeyOn,szDevNameLists);
	}
	else
	{
		//初始化审计员|操作员
		if (2 != ulKeyCount)
		{
			ulRet = OPE_ERR_DEV_NUMBER_ERR;  // 设备个数不正确
			goto err;
		}
	}

	// 打开设备
	ulRet = CAPI_KEY_ConnectDev(szDevNameLists,pszKeyOn,ulKeyTarget,&hDevSKF);
	if(ulRet)
	{
		goto err;
	}

	ulRet = SKF_EnumApplication(hDevSKF,szAppNameLists, &ulAppNameLists);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_EnumApplication");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if (ulAppNameLists < 2)
	{
		ulRet = OPE_ERR_OPEN_APPLICATION;
	}
	else
	{
		ulRet = SKF_OpenApplication(hDevSKF, szAppNameLists,&hAppSKF);
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_OpenApplication");
		FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	}

	ulRet = SKF_EnumContainer(hAppSKF,szConNameLists,&ulConNameLists);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_EnumContainer");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if(ulRet)
	{
		goto err;
	}

	if (NULL == CAPI_KEY_GetSubStringPtr(szConNameLists,DEFAULT_CONTAINER_ECC512))
	{
		ulRet = SKF_CreateContainer(hAppSKF, DEFAULT_CONTAINER_ECC512, &hConSKF);
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_CreateContainer");
		FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	}
	else
	{
		ulRet = SKF_OpenContainer(hAppSKF, DEFAULT_CONTAINER_ECC512, &hConSKF);
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_OpenContainer");
		FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	}

	if(ulRet)
	{
		goto err;
	}
	// 导出签名公钥

	if (2 == bIsSign)
	{
		// 需要修改
		ulRet = SKF_ExportECCExchangePubKey(hConSKF, &pubkeyBlob);
	}
	else
	{
		ulRet = SKF_ExportPublicKey(hConSKF, bIsSign,(BYTE *)&pubkeyBlob, &ulPubkeyBlobLen);
	}

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_ExportPublicKey");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if(ulRet)
	{
		goto err;
	}

	// 拷贝签名公钥
	memcpy(pbPK, pubkeyBlob.XCoordinate, 64);
	memcpy(pbPK+64, pubkeyBlob.YCoordinate, 64);

err:
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "FREE");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if (hConSKF)
	{
		SKF_CloseContainer(hConSKF);
	}
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "FREE");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if (hAppSKF)
	{
		SKF_CloseApplication(hAppSKF);
	}
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "FREE");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if (hDevSKF)
	{
		SKF_DisConnectDev(hDevSKF);
	}
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, " ");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);

	return ulRet;
}

// 导入密钥对512
unsigned int CAPI_KEY_ECC512ImportKeyPair(char * pszKeyOn,int ulKeyTarget,unsigned int bIsSign,unsigned char * pbKeyPair, char * pszPIN, unsigned int * pulRetry)
{
	char szDevNameLists[BUFFER_LEN_1K] = {0};
	char szAppNameLists[BUFFER_LEN_1K] = {0};
	char szConNameLists[BUFFER_LEN_1K];

	ULONG ulDevNameLists = BUFFER_LEN_1K;
	ULONG ulAppNameLists = BUFFER_LEN_1K;
	ULONG ulConNameLists = BUFFER_LEN_1K;

	HANDLE hDevSKF = NULL;
	HANDLE hConSKF = NULL;
	HANDLE hAppSKF = NULL;

	unsigned int ulRet = 0;
	int ulKeyCount = 0;

	// 枚举设备
	ulRet = SKF_EnumDev(TRUE,szDevNameLists,&ulDevNameLists);

	if(ulRet)
	{
		goto err;
	}

	CAPI_GetMulStringCount(szDevNameLists, &ulKeyCount);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_EnumDev");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "ulDevNameLists");
	FILE_LOG_NUMBER(file_log_name,(long)ulDevNameLists);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "szDevNameLists");
	FILE_LOG_STRING(file_log_name,szDevNameLists);

	if (0 == ulKeyCount)
	{
		ulRet = OPE_ERR_DEV_NUMBER_ZERO;  // 未插入设备
		goto err;
	}

	if (OPE_USB_TARGET_SELF == ulKeyTarget)
	{
		if (1 != ulKeyCount)
		{
			ulRet = OPE_ERR_DEV_NUMBER_ERR;  // 设备个数不正确
			goto err;
		}

		strcpy(pszKeyOn,szDevNameLists);
	}
	else
	{
		//初始化审计员|操作员
		if (2 != ulKeyCount)
		{
			ulRet = OPE_ERR_DEV_NUMBER_ERR;  // 设备个数不正确
			goto err;
		}
	}

	// 打开设备
	ulRet = CAPI_KEY_ConnectDev(szDevNameLists,pszKeyOn,ulKeyTarget,&hDevSKF);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_ConnectDev");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if(ulRet)
	{
		goto err;
	}

	ulRet = SKF_EnumApplication(hDevSKF,szAppNameLists, &ulAppNameLists);

	// 设备认证或者打开一个应用
	if (ulAppNameLists < 2)
	{
		ulRet = OPE_ERR_OPEN_APPLICATION;
	}
	else
	{
		ulRet = SKF_OpenApplication(hDevSKF, szAppNameLists,&hAppSKF);
	}

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "hAppSKFN");
	FILE_LOG_NUMBER(file_log_name,(long)hAppSKF);

	// 验证密码
	ulRet = SKF_VerifyPIN(hAppSKF, 1, pszPIN,(ULONG *)pulRetry);
	if(ulRet)
	{
		goto err;
	}

	// 枚举容器
	ulRet = SKF_EnumContainer(hAppSKF,szConNameLists,&ulConNameLists);
	if(ulRet)
	{
		goto err;
	}
	// 创建或打开容器
	if (NULL == CAPI_KEY_GetSubStringPtr(szConNameLists,DEFAULT_CONTAINER_ECC512))
	{
		ulRet = SKF_CreateContainer(hAppSKF, DEFAULT_CONTAINER_ECC512, &hConSKF);
	}
	else
	{
		ulRet = SKF_OpenContainer(hAppSKF, DEFAULT_CONTAINER_ECC512, &hConSKF);
	}

	if(ulRet)
	{
		goto err;
	}
	// 导入数字信封格式的交换密钥对
	if(2 == bIsSign)
	{
		// 导入交换密钥对
		ulRet = SKF_ImportECCExchangeKeyPair(hConSKF, (PENVELOPEDKEYBLOB)pbKeyPair);
	}
	else if(1 == bIsSign)
	{
		ulRet = SKF_ImportECCSignKeyPair(hConSKF, (PENVELOPEDKEYBLOB)pbKeyPair);
	}
	else
	{
		ulRet = SKF_ImportECCKeyPair(hConSKF, (PENVELOPEDKEYBLOB)pbKeyPair);
	}

	if(ulRet)
	{
		goto err;
	}

err:
	if (hConSKF)
	{
		SKF_CloseContainer(hConSKF);
	}

	if (hAppSKF)
	{
		SKF_CloseApplication(hAppSKF);
	}

	if (hDevSKF)
	{
		SKF_DisConnectDev(hDevSKF);
	}

	return ulRet;
}

// 导入证书512
unsigned int CAPI_KEY_ECC512ImportCert(char * pszKeyOn,int ulKeyTarget, unsigned int bIsSign,unsigned char * pbCert,unsigned int ulCertLen, char * pszPIN, unsigned int * pulRetry)
{
	char szDevNameLists[BUFFER_LEN_1K] = {0};
	char szAppNameLists[BUFFER_LEN_1K] = {0};
	char szConNameLists[BUFFER_LEN_1K];

	ULONG ulDevNameLists = BUFFER_LEN_1K;
	ULONG ulAppNameLists = BUFFER_LEN_1K;
	ULONG ulConNameLists = BUFFER_LEN_1K;

	HANDLE hDevSKF = NULL;
	HANDLE hConSKF = NULL;
	HANDLE hAppSKF = NULL;

	unsigned int ulRet = 0;
	int ulKeyCount = 0;

	// 枚举设备
	ulRet = SKF_EnumDev(TRUE,szDevNameLists,&ulDevNameLists);

	if(ulRet)
	{
		goto err;
	}

	CAPI_GetMulStringCount(szDevNameLists, &ulKeyCount);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_EnumDev");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "ulDevNameLists");
	FILE_LOG_NUMBER(file_log_name,(long)ulDevNameLists);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "szDevNameLists");
	FILE_LOG_STRING(file_log_name,szDevNameLists);

	if (0 == ulKeyCount)
	{
		ulRet = OPE_ERR_DEV_NUMBER_ZERO;  // 未插入设备
		goto err;
	}

	if (OPE_USB_TARGET_SELF == ulKeyTarget)
	{
		if (1 != ulKeyCount)
		{
			ulRet = OPE_ERR_DEV_NUMBER_ERR;  // 设备个数不正确
			goto err;
		}

		strcpy(pszKeyOn,szDevNameLists);
	}
	else
	{
		//初始化审计员|操作员
		if (2 != ulKeyCount)
		{
			ulRet = OPE_ERR_DEV_NUMBER_ERR;  // 设备个数不正确
			goto err;
		}
	}

	// 打开设备
	ulRet = CAPI_KEY_ConnectDev(szDevNameLists,pszKeyOn,ulKeyTarget,&hDevSKF);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_ConnectDev");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if(ulRet)
	{
		goto err;
	}

	ulRet = SKF_EnumApplication(hDevSKF,szAppNameLists, &ulAppNameLists);

	// 设备认证或者打开一个应用
	if (ulAppNameLists < 2)
	{
		ulRet = OPE_ERR_OPEN_APPLICATION;
	}
	else
	{
		ulRet = SKF_OpenApplication(hDevSKF, szAppNameLists,&hAppSKF);
	}

	// 验证密码
	ulRet = SKF_VerifyPIN(hAppSKF, 1, pszPIN,(ULONG *)pulRetry);
	if(ulRet)
	{
		goto err;
	}

	// 枚举容器
	ulRet = SKF_EnumContainer(hAppSKF,szConNameLists,&ulConNameLists);
	if(ulRet)
	{
		goto err;
	}
	// 创建或打开容器
	if (NULL == CAPI_KEY_GetSubStringPtr(szConNameLists,DEFAULT_CONTAINER_ECC512))
	{
		ulRet = SKF_CreateContainer(hAppSKF, DEFAULT_CONTAINER_ECC512, &hConSKF);
	}
	else
	{
		ulRet = SKF_OpenContainer(hAppSKF, DEFAULT_CONTAINER_ECC512, &hConSKF);
	}

	if(ulRet)
	{
		goto err;
	}

	if (bIsSign == 2)
	{
		ulRet = SKF_ImportExchangeCertificate(hConSKF, pbCert,ulCertLen);
	}
	else
	{
		ulRet = SKF_ImportCertificate(hConSKF, bIsSign,pbCert,ulCertLen);
	}

	// 导入证书
	if(ulRet)
	{
		goto err;
	}
err:
	if (hConSKF)
	{
		SKF_CloseContainer(hConSKF);
	}

	if (hAppSKF)
	{
		SKF_CloseApplication(hAppSKF);
	}

	if (hDevSKF)
	{
		SKF_DisConnectDev(hDevSKF);
	}

	return ulRet;
}

unsigned int CAPI_KEY_ECC512ConvertCipher(char * pszKeyOn,int ulKeyTarget, unsigned int bIsSign, unsigned char pbPK[64*2],void *pbIn,void *pbOut, char * pszPIN, unsigned int * pulRetry)
{
	char szDevNameLists[BUFFER_LEN_1K] = {0};
	char szAppNameLists[BUFFER_LEN_1K] = {0};
	char szConNameLists[BUFFER_LEN_1K];

	ULONG ulDevNameLists = BUFFER_LEN_1K;
	ULONG ulAppNameLists = BUFFER_LEN_1K;
	ULONG ulConNameLists = BUFFER_LEN_1K;

	HANDLE hDevSKF = NULL;
	HANDLE hConSKF = NULL;
	HANDLE hAppSKF = NULL;

	unsigned int ulRet = 0;
	int ulKeyCount = 0;
	
	HANDLE hSessionKey = NULL;
	ECCPUBLICKEYBLOB pk;


	// 枚举设备
	ulRet = SKF_EnumDev(TRUE,szDevNameLists,&ulDevNameLists);

	if(ulRet)
	{
		goto err;
	}

	CAPI_GetMulStringCount(szDevNameLists, &ulKeyCount);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_EnumDev");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "ulDevNameLists");
	FILE_LOG_NUMBER(file_log_name,(long)ulDevNameLists);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "szDevNameLists");
	FILE_LOG_STRING(file_log_name,szDevNameLists);

	if (0 == ulKeyCount)
	{
		ulRet = OPE_ERR_DEV_NUMBER_ZERO;  // 未插入设备
		goto err;
	}

	if (OPE_USB_TARGET_SELF == ulKeyTarget)
	{
		if (1 != ulKeyCount)
		{
			ulRet = OPE_ERR_DEV_NUMBER_ERR;  // 设备个数不正确
			goto err;
		}

		strcpy(pszKeyOn,szDevNameLists);
	}
	else
	{
		//初始化审计员|操作员
		if (2 != ulKeyCount)
		{
			ulRet = OPE_ERR_DEV_NUMBER_ERR;  // 设备个数不正确
			goto err;
		}
	}

	// 打开设备
	ulRet = CAPI_KEY_ConnectDev(szDevNameLists,pszKeyOn,ulKeyTarget,&hDevSKF);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_ConnectDev");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if(ulRet)
	{
		goto err;
	}

	ulRet = SKF_EnumApplication(hDevSKF,szAppNameLists, &ulAppNameLists);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_EnumApplication");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	// 设备认证或者打开一个应用
	if (ulAppNameLists < 2)
	{
		ulRet = OPE_ERR_OPEN_APPLICATION;
	}
	else
	{
		ulRet = SKF_OpenApplication(hDevSKF, szAppNameLists,&hAppSKF);
	}
	
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_OpenApplication");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	
	if(ulRet)
	{
		goto err;
	}
	

	// 验证密码
	ulRet = SKF_VerifyPIN(hAppSKF, 1, pszPIN,(ULONG *)pulRetry);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_VerifyPIN");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	
	if(ulRet)
	{
		goto err;
	}

	// 枚举容器
	ulRet = SKF_EnumContainer(hAppSKF,szConNameLists,&ulConNameLists);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_EnumContainer");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if(ulRet)
	{
		goto err;
	}
	// 创建或打开容器
	if (NULL == CAPI_KEY_GetSubStringPtr(szConNameLists,DEFAULT_CONTAINER_ECC512))
	{
		ulRet = SKF_CreateContainer(hAppSKF, DEFAULT_CONTAINER_ECC512, &hConSKF);
	}
	else
	{
		ulRet = SKF_OpenContainer(hAppSKF, DEFAULT_CONTAINER_ECC512, &hConSKF);
	}
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_OpenContainer");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);

	if(ulRet)
	{
		goto err;
	}

	ulRet = SKF_UnwrapKey(hConSKF,(ECCCIPHERBLOB*)pbIn, SGD_SMS4_ECB,&hSessionKey);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_UnwrapKey");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	if(ulRet)
	{
		goto err;
	}

	pk.BitLen = 512;
	memcpy(pk.XCoordinate,pbPK,64);
	memcpy(pk.YCoordinate,pbPK+64,64);

	ulRet = SKF_WrapKey(hConSKF,hSessionKey,&pk,(ECCCIPHERBLOB*)pbOut);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "SKF_WrapKey");
	FILE_LOG_NUMBER(file_log_name,(long)ulRet);
	// 导入证书
	if(ulRet)
	{
		goto err;
	}
err:
	if (hConSKF)
	{
		SKF_CloseContainer(hConSKF);
	}

	if (hAppSKF)
	{
		SKF_CloseApplication(hAppSKF);
	}

	if (hDevSKF)
	{
		SKF_DisConnectDev(hDevSKF);
	}

	return ulRet;
}


#endif