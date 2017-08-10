
#ifndef __KMS_CAPI_IBE__H_
#define __KMS_CAPI_IBE__H_

#include "SCCrypto.h"

#ifdef __cplusplus
extern "C" {
#endif


	int CAPI_IBE_Initialize(char * pszPIN, unsigned int * pulRetry, HANDLE *phDevice);

	int CAPI_IBE_Finalize(HANDLE hDevice);

	int CAPI_IBE_ExportSM2Pubkey(HANDLE hDevice, unsigned char pPubkey[32*2+1]);

	int CAPI_IBE_SetMetas(
		HANDLE hDevice,
		unsigned char *bUserID, unsigned int ulUserIDLen, 
		unsigned char *bPubKeySign, unsigned int ulPubKeySignLen, 
		unsigned char *bPriKeySign, unsigned int ulPriKeySignLen,
		unsigned char *bPubKeyExc, unsigned int ulPubKeyExcLen, 
		unsigned char *bPriKeyExc, unsigned int ulPriKeyExcLen);

#ifdef __cplusplus
}
#endif


#endif