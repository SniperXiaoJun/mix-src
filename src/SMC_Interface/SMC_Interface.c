#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>

#include "FILE_LOG.h"

#include "SMC_Interface.h"

#ifdef _DEBUG
#define DEBUG(format,...) printf("File: "__FILE__", Line: %05d: "format"\n", __LINE__, ##__VA_ARGS__);
#else
#define DEBUG(format,...)
#endif

#define DEFAULT_SMC_STORE_SM2_ROOT (L"DEFAULT_SMC_STORE_SM2_ROOT")
#define DEFAULT_SMC_STORE_SM2_USER (L"DEFAULT_SMC_STORE_SM2_USER")
#define DEFAULT_SMC_STORE_SM2_OTHERS (L"DEFAULT_SMC_STORE_SM2_OTHERS")
#define DEFAULT_SMC_STORE_SM2_CRL (L"DEFAULT_SMC_STORE_SM2_CRL")


HCERTSTORE WINAPI SMC_CertOpenStoreByName(
	_In_  unsigned int uiMsgAndCertEncodingType,
	_In_  unsigned int uiFlags, /* CERT_STORE_OPEN_EXISTING_FLAG */
	_In_  const void *pvPara
	);



BOOL WINAPI SMC_CertCreateSMCStores()
{
	//--------------------------------------------------------------------
	// Declare and initialize variables.
	BOOL ulRet = 0;
	unsigned int uiFlags= CERT_SYSTEM_STORE_CURRENT_USER;
	LPCWSTR pvSystemName = NULL;

	pvSystemName = DEFAULT_SMC_STORE_SM2_ROOT;  

	ulRet = CertRegisterSystemStore(
		pvSystemName,
		uiFlags,
		NULL,
		NULL);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "CertRegisterSystemStore");
	FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, ulRet);

	if(ulRet)
	{
		//DEBUG("System store %S is registered. \n",pvSystemName);
	}
	else
	{
		//DEBUG("The system store did not register. \n");
		goto err;
	}

	pvSystemName = DEFAULT_SMC_STORE_SM2_USER;  

	ulRet = CertRegisterSystemStore(
		pvSystemName,
		uiFlags,
		NULL,
		NULL);
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "CertRegisterSystemStore");
	FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, ulRet);
	if(ulRet)
	{
		//DEBUG("System store %S is registered. \n",pvSystemName);
	}
	else
	{
		//DEBUG("The system store did not register. \n");
		goto err;
	}


	pvSystemName = DEFAULT_SMC_STORE_SM2_OTHERS;  

	ulRet = CertRegisterSystemStore(
		pvSystemName,
		uiFlags,
		NULL,
		NULL);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "CertRegisterSystemStore");
	FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, ulRet);

	if(ulRet)
	{
		//DEBUG("System store %S is registered. \n",pvSystemName);
	}
	else
	{
		//DEBUG("The system store did not register. \n");
		goto err;
	}

	pvSystemName = DEFAULT_SMC_STORE_SM2_CRL;  

	ulRet = CertRegisterSystemStore(
		pvSystemName,
		uiFlags,
		NULL,
		NULL);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "CertRegisterSystemStore");
	FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, ulRet);

	if(ulRet)
	{
		///DEBUG("System store %S is registered. \n",pvSystemName);
	}
	else
	{
		//DEBUG("The system store did not register. \n");
		goto err;
	}

err:

	return ulRet;
}


BOOL SMC_CertDropSMCStore(_In_ unsigned int uiStoreID)
{
	const void *pvPara = NULL;

	BOOL ulRet = 0;

	switch(uiStoreID)
	{
	case DEFAULT_SMC_STORE_SM2_ROOT_ID:
		pvPara = DEFAULT_SMC_STORE_SM2_ROOT;
		break;
	case DEFAULT_SMC_STORE_SM2_USER_ID:
		pvPara = DEFAULT_SMC_STORE_SM2_USER;
		break;
	case DEFAULT_SMC_STORE_SM2_OTHERS_ID:
		pvPara = DEFAULT_SMC_STORE_SM2_OTHERS;
		break;
	case DEFAULT_SMC_STORE_SM2_CRL_ID:
		pvPara = DEFAULT_SMC_STORE_SM2_CRL;
		break;
	default:
		return FALSE;
	}

	ulRet = CertUnregisterSystemStore(pvPara,CERT_STORE_DELETE_FLAG);

	if(ulRet)
	{
		
	}
	else
	{
		
		goto err;
	}

err:

	return ulRet;
}

HCERTSTORE WINAPI SMC_CertOpenStore(
	_In_  unsigned int uiMsgAndCertEncodingType,
	_In_  unsigned int uiFlags,
	_In_  unsigned int uiStoreID
	)
{
	const void *pvPara = NULL;

	switch(uiStoreID)
	{
	case DEFAULT_SMC_STORE_SM2_ROOT_ID:
		pvPara = DEFAULT_SMC_STORE_SM2_ROOT;
		break;
	case DEFAULT_SMC_STORE_SM2_USER_ID:
		pvPara = DEFAULT_SMC_STORE_SM2_USER;
		break;
	case DEFAULT_SMC_STORE_SM2_OTHERS_ID:
		pvPara = DEFAULT_SMC_STORE_SM2_OTHERS;
		break;
	case DEFAULT_SMC_STORE_SM2_CRL_ID:
		pvPara = DEFAULT_SMC_STORE_SM2_CRL;
		break;
	default:
		return NULL;
	}

	return SMC_CertOpenStoreByName(uiMsgAndCertEncodingType, uiFlags, pvPara);
}

HCERTSTORE WINAPI SMC_CertOpenStoreByName(
	_In_  unsigned int uiMsgAndCertEncodingType,
	_In_  unsigned int uiFlags, /* CERT_STORE_OPEN_EXISTING_FLAG */
	_In_  const void *pvPara
	)
{
	HCERTSTORE hSysStore = NULL;
	if(hSysStore = CertOpenStore(
		CERT_STORE_PROV_SYSTEM,          // The store provider type
		uiMsgAndCertEncodingType,        // The encoding type is not needed
		NULL,                            // Use the default HCRYPTPROV
		uiFlags,						 // Set the store location in a registry location
		pvPara							 // The store name as a Unicode string
		))
	{
		DEBUG("The system store was created successfully.\n");
	}
	else
	{
		DEBUG("An error occurred during creation "
			"of the system store!\n");

		goto err;
	}

err:

	return hSysStore;

	////-------------------------------------------------------------------
	//// Open a system store, in this case, the My store.

	//HCERTSTORE hSysStore = NULL;
	//if(hSysStore = CertOpenStore(
	//	CERT_STORE_PROV_SYSTEM,          // The store provider type
	//	0,                               // The encoding type is
	//	// not needed
	//	NULL,                            // Use the default HCRYPTPROV
	//	CERT_SYSTEM_STORE_CURRENT_USER,  // Set the store location in a
	//	// registry location
	//	L"MY"                            // The store name as a Unicode 
	//	// string
	//	))
	//{
	//	printf("The system store was created successfully.\n");
	//}
	//else
	//{
	//	printf("An error occurred during creation "
	//		"of the system store!\n");
	//	exit(1);
	//}

	//// Other common system stores include "Root", "Trust", and "Ca".


	////-------------------------------------------------------------------
	//// Open a memory store. 

	//HCERTSTORE hMemStore = NULL;
	//if(hMemStore = CertOpenStore(
	//	CERT_STORE_PROV_MEMORY,   // The memory provider type
	//	0,                        // The encoding type is not needed
	//	NULL,                     // Use the default HCRYPTPROV
	//	0,                        // Accept the default uiFlags
	//	NULL                      // pvPara is not used
	//	))
	//{
	//	printf("The memory store was created successfully.\n");
	//}
	//else
	//{
	//	printf("An error occurred during creation "
	//		"of the memory store!\n");
	//	exit(1);
	//}

	////-------------------------------------------------------------------
	//// Open a read-only store from disk.

	//HANDLE       hFile = NULL;
	//HCERTSTORE   hFileStore = NULL;
	//LPCSTR       pszFileName = "TestStor2.sto";
	//SECURITY_ATTRIBUTES  sa;        // For DACL

	//// Create a DACL to use when opening the file.
	//sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	//sa.bInheritHandle = FALSE;  

	//// Call function to set the DACL. The DACL is set in the 
	//// SECURITY_ATTRIBUTES lpSecurityDescriptor member.
	//if (!CreateMyDACL(&sa))
	//{
	//	// Error encountered; generate message and exit.
	//	printf("Failed CreateMyDACL.\n");
	//	exit(1);
	//}

	//// Obtain the file handle of an existing file.
	//if (hFile = CreateFile(
	//	pszFileName,                  // The file name
	//	GENERIC_READ|GENERIC_WRITE,   // Access mode: Read from and
	//	// write to this file
	//	0,                            // Share mode
	//	&sa,                          // Uses the DACL created 
	//	// previously 
	//	OPEN_ALWAYS,                  // How to create
	//	FILE_ATTRIBUTE_NORMAL,        // File attributes
	//	NULL))                        // Template
	//{
	//	printf("The file was opened successfully.\n");
	//}
	//else
	//{
	//	printf("An error occurred during opening of the file!\n");
	//	exit(1);
	//}

	////-------------------------------------------------------------------
	////  This file can contain data before the store itself.
	////  At this point, read and use data in the open file that precedes
	////  the serialized certificate store data. 
	////  To open the certificate store, the file pointer must
	////  be placed at the beginning of the certificate store data.

	////-------------------------------------------------------------------
	////  Open the store.

	//if(hFileStore = CertOpenStore(
	//	CERT_STORE_PROV_FILE,     // Load certificates from a file
	//	0,                        // Encoding type not used
	//	NULL,                     // Use the default HCRYPTPROV
	//	CERT_STORE_READONLY_FLAG, // Read-only store
	//	hFile                     // The handle for the open file 
	//	// that is the source of the 
	//	// certificates
	//	))
	//{
	//	printf("The file store was created successfully.\n");
	//}
	//else
	//{
	//	printf("An error occurred during creation of the file store!\n");
	//	exit(1);
	//}

	////-------------------------------------------------------------------
	//// After processing, close the certificate stores and the file.

	//if(CertCloseStore(
	//	hSysStore, 
	//	CERT_CLOSE_STORE_CHECK_FLAG))
	//{
	//	printf("The system store was closed successfully.\n");
	//}
	//else
	//{
	//	printf("An error occurred during closing of the "
	//		"system store.\n");
	//}

	//if(CertCloseStore(
	//	hMemStore, 
	//	CERT_CLOSE_STORE_CHECK_FLAG))
	//{
	//	printf("The memory store was closed successfully.\n");
	//}
	//else
	//{
	//	printf("An error occurred during closing of the "
	//		"memory store.\n");
	//}

	//if(CertCloseStore(
	//	hFileStore, 
	//	CERT_CLOSE_STORE_CHECK_FLAG))
	//{
	//	printf("The file store was closed successfully.\n");
	//}
	//else
	//{
	//	printf("An error occurred during closing of the file store.\n");
	//}

	//if(CloseHandle(hFile))
	//{
	//	printf("The file was closed successfully.\n");
	//}
	//else
	//{
	//	printf("An error occurred during closing of the file.\n");
	//}
}


BOOL WINAPI SMC_CertCloseStore(
	_In_  HCERTSTORE hCertStore,
	_In_  unsigned int uiFlags
	)
{
	return CertCloseStore(hCertStore, uiFlags);
}


BOOL WINAPI SMC_CertAddCertificateContextToStore(
	_In_       HCERTSTORE hCertStore,
	_In_       PCCERT_CONTEXT pCertContext,
	_In_       unsigned int uiAddDisposition
	)
{
	BOOL ulRet = CertAddCertificateContextToStore(hCertStore,pCertContext,uiAddDisposition, NULL);
	
	return ulRet;
}


BOOL WINAPI SMC_CertDeleteCertificateFromStore(
	_In_  PCCERT_CONTEXT pCertContext
	)
{
	return CertDeleteCertificateFromStore(pCertContext);
}


PCCERT_CONTEXT WINAPI SMC_CertEnumCertificatesInStore(
	_In_  HCERTSTORE hCertStore,
	_In_  PCCERT_CONTEXT pPrevCertContext
	)
{
	return CertEnumCertificatesInStore(hCertStore, pPrevCertContext);
}


PCCERT_CONTEXT WINAPI SMC_CertFindCertificateInStore(
	_In_  HCERTSTORE hCertStore,
	_In_  unsigned int uiCertEncodingType,
	_In_  unsigned int uiFindType,
	_In_  const void *pvFindPara,
	_In_  PCCERT_CONTEXT pPrevCertContext
	)
{
	PCCERT_CONTEXT pCertContext = NULL;

	if(pCertContext = CertFindCertificateInStore(
		hCertStore,
		uiCertEncodingType,           // Use X509_ASN_ENCODING.
		0,                          // No uiFlags needed. 
		uiFindType,      // Find a certificate with a
		// subject that matches the string
		// in the next parameter.
		pvFindPara ,           // The Unicode string to be found
		// in a certificate's subject.
		pPrevCertContext))                      // NULL for the first call to the
		// function. In all subsequent
		// calls, it is the last pointer
		// returned by the function.
	{
		DEBUG("The desired certificate was found. \n");
	}
	else
	{
		DEBUG("Could not find the desired certificate.\n");
	}

	return pCertContext;
}



BOOL WINAPI SMC_CertSetCertificateContextProperty(
	_In_  PCCERT_CONTEXT pCertContext,
	_In_  unsigned int uiPropId,
	_In_  unsigned int uiFlags,
	_In_  const void *pvData
	)
{
	if (uiPropId != CERT_DESC_PROP_ID)
	{
		return CertSetCertificateContextProperty(pCertContext,uiPropId,uiFlags,pvData);
	}
	else
	{
		const SK_CERT_DESC_PROPERTY * descProperty = (const SK_CERT_DESC_PROPERTY *)pvData;

		if (NULL == descProperty)
		{
			return CertSetCertificateContextProperty(pCertContext,uiPropId,CERT_STORE_NO_CRYPT_RELEASE_FLAG,pvData);
		}
		else
		{
			CRYPT_DATA_BLOB dataBlob = {0};

			dataBlob.cbData = sizeof(SK_CERT_DESC_PROPERTY);

			dataBlob.pbData = (byte *)descProperty;

			return CertSetCertificateContextProperty(pCertContext,uiPropId,CERT_STORE_NO_CRYPT_RELEASE_FLAG,&dataBlob);
		}
	}
}

BOOL WINAPI SMC_CertGetCertificateContextProperty(
	_In_     PCCERT_CONTEXT pCertContext,
	_In_     unsigned int uiPropId,
	_Out_    void *pvData,
	_Inout_  unsigned int *pcbData
	)
{
	return CertGetCertificateContextProperty(pCertContext, uiPropId, pvData, pcbData);
}

BOOL WINAPI SMC_CertExportPublicKeyInfo(
	_In_     PCCERT_CONTEXT pCertContext,
	_Out_    PCERT_PUBLIC_KEY_INFO pInfo,
	_Inout_  unsigned int *pcbInfo
	)
{
	if (NULL == pcbInfo)
	{
		return FALSE;
	}

	if (NULL == pInfo)
	{
		*pcbInfo = sizeof(CERT_PUBLIC_KEY_INFO);
		return TRUE;
	}

	if (*pcbInfo != sizeof(CERT_PUBLIC_KEY_INFO))
	{
		return FALSE;
	}

	*pcbInfo = sizeof(CERT_PUBLIC_KEY_INFO);

	memcpy(pInfo,&(pCertContext->pCertInfo->SubjectPublicKeyInfo) ,*pcbInfo);

	return TRUE;
}

LONG WINAPI SMC_CertVerifyTimeValidity(
	_In_  LPFILETIME pTimeToVerify,
	_In_  PCERT_INFO pCertInfo
	)
{
	return CertVerifyTimeValidity(pTimeToVerify, pCertInfo);
}

PCCERT_CONTEXT WINAPI SMC_CertCreateCertificateContext(
	__in unsigned int uiCertEncodingType,
	__in_bcount(cbCertEncoded) const BYTE *pbCertEncoded,
	__in unsigned int cbCertEncoded
	)
{
	return CertCreateCertificateContext(uiCertEncodingType, pbCertEncoded, cbCertEncoded);
}

BOOL WINAPI SMC_CertFreeCertificateContext(
	__in_opt PCCERT_CONTEXT pCertContext	
	)
{
	return CertFreeCertificateContext(pCertContext);
}

#include "openssl_func_def.h"

BOOL WINAPI SMC_CertVerifyCertificateSignature(	
	_In_  BYTE *pbCertEncoded,
	_In_  unsigned int cbCertEncoded,
	_In_  PCERT_PUBLIC_KEY_INFO pPublicKey)
{
	BOOL ulRet = 0;

	if (pPublicKey->PublicKey.cbData != SM2_BYTES_LEN * 2 + 1)
	{
		ulRet = FALSE;
		goto err;
	}

	ulRet = OpenSSL_Initialize();
	if (ulRet)
	{

	}

	ulRet = OpenSSL_SM2VerifyCert(pbCertEncoded, cbCertEncoded,0,
			pPublicKey->PublicKey.pbData + 1 , SM2_BYTES_LEN,
			pPublicKey->PublicKey.pbData + 1 + SM2_BYTES_LEN, SM2_BYTES_LEN);
	
	if (0 == ulRet)
	{
		ulRet = TRUE;
	}
	else{
		ulRet = FALSE;
	}


err:
	OpenSSL_Finalize();

	return ulRet;
}


unsigned long WINAPI SMC_ImportUserCert(BYTE * pbCert, unsigned long ulCertLen, SK_CERT_DESC_PROPERTY * pCertProperty)
{
	unsigned long ulRet = 0;
	PCCERT_CONTEXT certContext_IN = NULL;
	HCERTSTORE hCertStore;

	// 瀵煎叆璇佷功

	// 鍒涘缓瀛樺偍鍖?
	ulRet = SMC_CertCreateSMCStores();
	if (!ulRet)
	{
		ulRet = EErr_SMC_CREATE_STORE;
		goto err;
	}

	// 鎵撳紑瀛樺偍鍖?
	hCertStore = SMC_CertOpenStore(0,CERT_SYSTEM_STORE_CURRENT_USER, DEFAULT_SMC_STORE_SM2_USER_ID);
	if (NULL == hCertStore)
	{
		ulRet = EErr_SMC_OPEN_STORE;
		goto err;
	}

	// 鍒涘缓涓婁笅鏂?
	certContext_IN = SMC_CertCreateCertificateContext(X509_ASN_ENCODING, (BYTE *)pbCert,ulCertLen);
	if (!certContext_IN)
	{
		ulRet = EErr_SMC_CREATE_CERT_CONTEXT;
		goto err;
	}

	// 璁剧疆灞炴€?
	ulRet = SMC_CertSetCertificateContextProperty(certContext_IN, CERT_DESC_PROP_ID,CERT_STORE_NO_CRYPT_RELEASE_FLAG, pCertProperty);
	if (!ulRet)
	{
		ulRet = EErr_SMC_SET_CERT_CONTEXT_PROPERTY;
		goto err;

	}

	// 淇濆瓨璇佷功
	ulRet = SMC_CertAddCertificateContextToStore(hCertStore,certContext_IN, CERT_STORE_ADD_REPLACE_EXISTING);
	if(!ulRet)
	{
		ulRet = EErr_SMC_ADD_CERT_TO_STORE;
		goto err;
	}

err:

	if(certContext_IN)
	{
		// 閲婃斁涓婁笅鏂?
		ulRet = SMC_CertFreeCertificateContext(certContext_IN);
	}

	if (hCertStore)
	{
		// 鍏抽棴瀛樺偍鍖?
		ulRet = SMC_CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
	}

	return ulRet;
}


PCCERT_CONTEXT WINAPI SMC_CertDuplicateCertificateContext(
	_In_ PCCERT_CONTEXT pCertContext
	)
{
	return CertDuplicateCertificateContext(pCertContext);
}



unsigned int WINAPI WTF_FindEnCertificateByCertDescProperty(
	_In_ SK_CERT_DESC_PROPERTY * pCertDescProperty, _Out_ unsigned char * pbCert, _Inout_ unsigned int * pulCertLen
	);

LONG WINAPI SMC_CertFindEnCertificateByCertDescProperty(
	_In_ SK_CERT_DESC_PROPERTY * pCertDescProperty, _Out_ unsigned char * pbCert, _Inout_ unsigned int * pulCertLen
	)
{
	unsigned long ulRet = -1;
	PCCERT_CONTEXT certContext_DUL = NULL;
	HCERTSTORE hCertStore;


	ulRet = SMC_CertCreateSMCStores();
	if (!ulRet)
	{
		ulRet = EErr_SMC_CREATE_STORE;
		goto err;
	}

	hCertStore = SMC_CertOpenStore(0,CERT_SYSTEM_STORE_CURRENT_USER, DEFAULT_SMC_STORE_SM2_USER_ID);
	if (NULL == hCertStore)
	{
		ulRet = EErr_SMC_OPEN_STORE;
		goto err;
	}

	do 
	{
		unsigned int ulOutLen = 0;
		PCCERT_CONTEXT certContext_OUT = NULL;
		// 从第一个开始

		certContext_OUT = SMC_CertEnumCertificatesInStore(hCertStore, certContext_DUL);

		// 获取ATTR
		if (NULL != certContext_OUT)
		{
			SK_CERT_DESC_PROPERTY * descProperty_OUT = NULL;

			if(certContext_OUT)
			{
				certContext_DUL = SMC_CertDuplicateCertificateContext(certContext_OUT);
			}

			ulRet = SMC_CertGetCertificateContextProperty(certContext_OUT, CERT_DESC_PROP_ID, NULL,&ulOutLen);
			descProperty_OUT = (SK_CERT_DESC_PROPERTY * )malloc(ulOutLen);
			ulRet = SMC_CertGetCertificateContextProperty(certContext_OUT, CERT_DESC_PROP_ID, descProperty_OUT,&ulOutLen);

			if((descProperty_OUT->bSignType ==0 ) && 0 == memcmp(descProperty_OUT,pCertDescProperty,(char *)&(descProperty_OUT->bSignType) - (char *)&(descProperty_OUT->szSKFName)))
			{
				if (pbCert == 0)
				{
					*pulCertLen = certContext_OUT->cbCertEncoded;
					ulRet = EErr_SMC_OK;
				}
				else if(*pulCertLen < certContext_OUT->cbCertEncoded)
				{
					*pulCertLen = certContext_OUT->cbCertEncoded;
					ulRet = EErr_SMC_MEM_LES;
				}
				else
				{
					*pulCertLen = certContext_OUT->cbCertEncoded;
					memcpy(pbCert, certContext_OUT->pbCertEncoded, *pulCertLen);
					ulRet = EErr_SMC_OK;
				}
			}


			free(descProperty_OUT);


			if(certContext_OUT)
			{
				SMC_CertFreeCertificateContext(certContext_OUT);
			}

			if (EErr_SMC_OK == ulRet)
			{
				break;
			}
		}
		else
		{
			certContext_DUL = NULL;
		}
	}while(certContext_DUL);

err:
	if(certContext_DUL)
	{
		SMC_CertFreeCertificateContext(certContext_DUL);
	}

	if (hCertStore)
	{
		SMC_CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
	}

	return ulRet;
}

LONG WINAPI SMC_CertGetCertificateContextPropertyByCert(
	_In_ unsigned char * pbSignCert, unsigned int ulSignCert, _Out_ SK_CERT_DESC_PROPERTY * pCertDescProperty
	)
{
	unsigned long ulRet = -1;
	PCCERT_CONTEXT certContext_DUL = NULL;
	HCERTSTORE hCertStore;


	ulRet = SMC_CertCreateSMCStores();
	if (!ulRet)
	{
		ulRet = EErr_SMC_CREATE_STORE;
		goto err;
	}

	hCertStore = SMC_CertOpenStore(0,CERT_SYSTEM_STORE_CURRENT_USER, DEFAULT_SMC_STORE_SM2_USER_ID);
	if (NULL == hCertStore)
	{
		ulRet = EErr_SMC_OPEN_STORE;
		goto err;
	}

	do 
	{
		unsigned int ulOutLen = 0;
		PCCERT_CONTEXT certContext_OUT = NULL;
		// 从第一个开始

		certContext_OUT = SMC_CertEnumCertificatesInStore(hCertStore, certContext_DUL);

		// 获取ATTR
		if (NULL != certContext_OUT)
		{
			SK_CERT_DESC_PROPERTY * descProperty_OUT = NULL;

			if(certContext_OUT)
			{
				certContext_DUL = SMC_CertDuplicateCertificateContext(certContext_OUT);
			}

			ulRet = SMC_CertGetCertificateContextProperty(certContext_OUT, CERT_DESC_PROP_ID, NULL,&ulOutLen);
			descProperty_OUT = (SK_CERT_DESC_PROPERTY * )malloc(ulOutLen);
			ulRet = SMC_CertGetCertificateContextProperty(certContext_OUT, CERT_DESC_PROP_ID, descProperty_OUT,&ulOutLen);

			if(0 == memcmp(certContext_OUT->pbCertEncoded,pbSignCert, certContext_OUT->cbCertEncoded))
			{
				memcpy(pCertDescProperty, descProperty_OUT, sizeof(SK_CERT_DESC_PROPERTY));
				ulRet = EErr_SMC_OK;
			}

			free(descProperty_OUT);


			if(certContext_OUT)
			{
				SMC_CertFreeCertificateContext(certContext_OUT);
			}

			if (EErr_SMC_OK == ulRet)
			{
				break;
			}
		}
		else
		{
			certContext_DUL = NULL;
		}
	}while(certContext_DUL);

err:
	if(certContext_DUL)
	{
		SMC_CertFreeCertificateContext(certContext_DUL);
	}

	if (hCertStore)
	{
		SMC_CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
	}

	return ulRet;
}


LONG WINAPI SMC_CertFindEnCertificateBySignCert(
	_In_ unsigned char * pbSignCert, unsigned int ulSignCert, _Out_ unsigned char * pbCert, _Inout_ unsigned int * pulCertLen
	)
{
	unsigned int ulRet = -1;
	SK_CERT_DESC_PROPERTY descProperty;
	
	ulRet = SMC_CertGetCertificateContextPropertyByCert(pbSignCert,ulSignCert,&descProperty);
	if (ulRet)
	{
		goto err;
	}

	ulRet = SMC_CertFindEnCertificateByCertDescProperty(&descProperty,pbCert, pulCertLen);
err:

	return ulRet;
}

