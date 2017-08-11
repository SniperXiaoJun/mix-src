
#include "KMS_CAPI_IBE.h"
#include "SCCrypto.h"
#include "o_all_type_def.h"
#pragma comment(lib, "SCCrypto.lib")

int CAPI_IBE_Initialize(char * pszPIN, unsigned int * pulRetry, HANDLE *phDevice)
{
	DWORD ulRet;

	DWORD ulDevsLen, ulDevsNum;
	char szDevs[SCCRYPT_TF_MAX_DEV_NAME_LEN*4] = {0};


	ulDevsNum = 0;
	ulDevsLen = sizeof(szDevs);
	memset(szDevs, 0x00, ulDevsLen);

	*phDevice = 0;

	ulRet = SC_ListDevs(szDevs, &ulDevsLen, &ulDevsNum);
	if (0 != ulRet)
	{
		goto err;
	}
	if (1 != ulDevsNum)
	{
		ulRet = OPE_ERR_DEV_NUMBER_ERR;
		goto err;
	}

	ulRet = SC_ConnectDev(szDevs, phDevice);
	if(0 != ulRet)
	{
		goto err;
	}

	ulRet = SC_VerifyPIN(*phDevice, (unsigned char*)pszPIN, strlen(pszPIN), (DWORD*)pulRetry);

err:

	if (ulRet)
	{
		if (*phDevice)
		{
			SC_CryptFinal(*phDevice);
		}
	}

	return ulRet;
}


int CAPI_IBE_Finalize(HANDLE hDevice)
{
	return SC_DisconnectDev(hDevice);
}

int CAPI_IBE_ExportSM2Pubkey(HANDLE hDevice, unsigned char pPubkey[32*2])
{
	DWORD dwPubkeyLen = 32*2+1;
	unsigned char pPubkeyTmp[32*2+1] = {0};
	DWORD ulRet;

	ulRet=  SC_ExportSM2PubKey(hDevice, pPubkeyTmp, &dwPubkeyLen);

	memcpy(pPubkey, pPubkeyTmp+1,32*2);

	return ulRet;
}

int CAPI_IBE_SetMetas(
	HANDLE hDevice,
	unsigned char *bUserID, unsigned int ulUserIDLen, 
	unsigned char *bPubKeySign, unsigned int ulPubKeySignLen, 
	unsigned char *bPriKeySign, unsigned int ulPriKeySignLen,
	unsigned char *bPubKeyExc, unsigned int ulPubKeyExcLen, 
	unsigned char *bPriKeyExc, unsigned int ulPriKeyExcLen
	)
{
	return SC_InstallSM9KeyPair(hDevice, 0, bUserID, ulUserIDLen, bPubKeySign, ulPubKeySignLen, bPriKeySign, ulPriKeySignLen,
		bPubKeyExc, ulPubKeyExcLen, bPriKeyExc, ulPriKeyExcLen);
}
