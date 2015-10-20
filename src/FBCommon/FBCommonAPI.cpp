/**********************************************************\

  Auto-generated FBCommonAPI.cpp

\**********************************************************/

#include "JSObject.h"
#include "variant_list.h"
#include "DOM/Document.h"
#include "global/config.h"
#include "FBCommonAPI.h"
#include "Dbt.h"
#include <Windows.h>
#include "FILE_LOG.h"
#include "modp_b64.h"
#include "o_all_func_def.h"
#include "openssl_func_def.h"
#include "SKFInterface.h"
#include "sm3.h"
#include "sm2.h"
#include "KMS_CAPI.h"
#include "encodes_witch.h"
#include "../NPBankAPILib/WTF_Interface.h"

static char DEFAULT_CONTAINER[] = "ContainerSM2";
static char DEFAULT_APPLICATION[] = "DEFAULT_APPLICATION";

void GetArrayLength(FB::VariantList& variantList, int* pLength);
void GetArrayWStrOfIndex(FB::VariantList& variantList, int index, wchar_t * pValue, int * pLen);
void GetArrayStrOfIndex(FB::VariantList& variantList, int index, char * pValue, int * pLen);
void GetArrayNumberOfIndex(FB::VariantList& variantList, int index, int * pValue);


DWORD WINAPI ThreadFuncSKFGenSM2KeyPair(LPVOID aThisClass);
DWORD WINAPI ThreadFuncSKFImportSM2KeyPair(LPVOID aThisClass);
DWORD WINAPI ThreadFuncSKFGenCSR(LPVOID aThisClass);
DWORD WINAPI ThreadFuncSKFImportCerts(LPVOID aThisClass);
DWORD WINAPI ThreadFuncSKFSignValidCode(LPVOID aThisClass);


LRESULT CALLBACK WndProc (HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
DWORD __stdcall CreateDlg(IN void* pParam);
void __stdcall CreateDlgThread();

std::vector<FBCommonAPI *> g_plgnObjVector;// 插拔KEY事件检测   用于登录
std::vector<FBCommonAPI *> g_plgnObjVectorLoginKeyOnOff;// 插拔KEY事件检测   用于锁屏


// 认证KEY
OPT_ST_USB_META FBCommonAPI::m_stMetaAuth = {0};
// 证书KEY
OPT_ST_USB_META FBCommonAPI::m_stMetaCert = {0};
// 即将添加的KEY
OPT_ST_USB_META FBCommonAPI::m_stMetaAuthAdd = {0};

char FBCommonAPI::m_szAuthKey[BUFFER_LEN_1K];        // 认证KEY（登录KEY）


HINSTANCE g_hInstance;

extern unsigned int __stdcall UI_ShowCert(SK_CERT_CONTENT * pCertContent);


DWORD WINAPI ThreadFuncShowCert(LPVOID aThisClass)
{
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__,"");

	FBCommonAPI * thisClass = (FBCommonAPI*)aThisClass;

	SK_CERT_CONTENT * pCertContent = (SK_CERT_CONTENT *)malloc(sizeof(SK_CERT_CONTENT) + thisClass->m_iCertShowLen);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__,"");

	memset(pCertContent, 0, sizeof(SK_CERT_CONTENT) + thisClass->m_iCertShowLen);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__,"pCertContent");
	FILE_LOG_HEX(file_log_name, (unsigned char *)pCertContent, sizeof(SK_CERT_CONTENT) + thisClass->m_iCertShowLen);

	pCertContent->nValueLen = thisClass->m_iCertShowLen;

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__,"thisClass->m_iCertShowLen");
	FILE_LOG_NUMBER(file_log_name, thisClass->m_iCertShowLen);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__,"pCertContent->nValueLen");
	FILE_LOG_NUMBER(file_log_name, pCertContent->nValueLen);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__,"pCertContent");
	FILE_LOG_HEX(file_log_name, (unsigned char *)pCertContent, sizeof(SK_CERT_CONTENT) + thisClass->m_iCertShowLen);

	memcpy(((char *)pCertContent) + sizeof(SK_CERT_CONTENT),thisClass->m_szCertShow,pCertContent->nValueLen);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__,"pCertContent");
	FILE_LOG_HEX(file_log_name, (unsigned char *)pCertContent, sizeof(SK_CERT_CONTENT) + thisClass->m_iCertShowLen);

	if (NULL == pCertContent)
	{
		goto err;
	}

	UI_ShowCert(pCertContent);

err:

	if (pCertContent)
	{
		free(pCertContent);
	}
	
	return 0;
}

LRESULT CALLBACK WndProc (HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	int i = 0;

	Sleep(1000);

	switch(message)
	{
		// Maybe WinCE OS does not support PNP.
		// When you use the PNP notifications, please make sure the WinCE OS supports it.
	case WM_DEVICECHANGE:
		if(wParam == DBT_DEVICEARRIVAL || wParam == DBT_DEVICEREMOVECOMPLETE)
		{
			//g_plgnObjVector[i]->ulResult = CAPI_KEY_GetMeta(g_plgnObjVector[i]->m_szAuthKey, OPE_USB_TARGET_SELF, &(g_plgnObjVector[i]->m_stMetaAuth));

			for (i = 0; i < g_plgnObjVector.size(); i++)
			{
				(g_plgnObjVector[i])->fire_usbevent(g_plgnObjVector[i]->m_stMetaAuth.szName,g_plgnObjVector[i]->ulResult);
			}

		}

		if (g_plgnObjVectorLoginKeyOnOff.size() > 0)
		{
			g_plgnObjVectorLoginKeyOnOff[i]->ulResult = CAPI_KEY_CheckOnOff(g_plgnObjVectorLoginKeyOnOff[i]->m_szAuthKey,OPE_USB_TARGET_SELF, &(g_plgnObjVectorLoginKeyOnOff[i]->m_stMetaAuth));

			for (i = 0; i < g_plgnObjVectorLoginKeyOnOff.size(); i++)
			{
				(g_plgnObjVectorLoginKeyOnOff[i])->fire_usbeventonoff(g_plgnObjVectorLoginKeyOnOff[i]->m_stMetaAuth.szName,g_plgnObjVectorLoginKeyOnOff[i]->ulResult);
			}

		}

		break;
	default:
		break;
	}

	return DefWindowProc (hWnd, message, wParam, lParam) ;
}

DWORD __stdcall CreateDlg(IN void* pParam)
{
	static TCHAR szAppName[] = TEXT("CYSD_CSPUPI_DLG_NAME_A581FDC3-B26E-4809-A037-F8901D84B57D") ;
	HWND         hWnd ;
	MSG          msg ;
	WNDCLASS     wndClass;
	BOOL bRet;

	wndClass.style         = CS_HREDRAW | CS_VREDRAW ;
	wndClass.lpfnWndProc   = WndProc ;
	wndClass.cbClsExtra    = 0 ;
	wndClass.cbWndExtra    = 0 ;
	wndClass.hInstance     = g_hInstance ;
#ifdef _WIN32_WCE	// WinCE
	wndClass.hIcon         = NULL;
#else				// Windows
	wndClass.hIcon         = LoadIcon (NULL, IDI_APPLICATION) ;
#endif
	wndClass.hCursor       = LoadCursor (NULL, IDC_ARROW) ;
	wndClass.hbrBackground = (HBRUSH) GetStockObject (WHITE_BRUSH) ;
	wndClass.lpszMenuName  = NULL ;
	wndClass.lpszClassName = szAppName ;

	if (! RegisterClass (&wndClass))
	{
		return FALSE;
	}
	hWnd = CreateWindow (szAppName,					 // window class name
		TEXT (""),					 // window caption
		(WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX),	//WS_OVERLAPPEDWINDOW,		 // window style
		CW_USEDEFAULT,				 // initial x position
		CW_USEDEFAULT,				 // initial y position
		CW_USEDEFAULT,				 // initial x size
		CW_USEDEFAULT,				 // initial y size
		NULL,						 // parent window handle
		NULL,						 // window menu handle
		g_hInstance,				 // program instance handle
		NULL) ;					 // creation parameters

	ShowWindow (hWnd, SW_HIDE) ;
	UpdateWindow (hWnd);
	while ((bRet=GetMessage (&msg, hWnd, 0, 0))!=0)
	{
		if(bRet==-1)
		{
			return FALSE;
		}
		else
		{
			TranslateMessage (&msg) ;
			DispatchMessage (&msg) ;
		}
	}

	return TRUE;
}

			

DWORD ulThreadID = 0; // 监视设备插拔线程句柄

void __stdcall CreateDlgThread()
{
	if (0 == ulThreadID)
	{
		HANDLE hMonitorHandle=NULL; // 监视设备插拔线程句柄

		DWORD ulSysVer;
		SECURITY_ATTRIBUTES sa;
		SECURITY_DESCRIPTOR sd;
		memset(&sa,0x00,sizeof(SECURITY_ATTRIBUTES));
		sa.nLength = sizeof(SECURITY_ATTRIBUTES);
		sa.bInheritHandle = TRUE;

		ulSysVer=GetVersion();

		//if (!(ulSysVer & 0x80000000))	// win2K,XP,2003
		//{		
		InitializeSecurityDescriptor(&sd,SECURITY_DESCRIPTOR_REVISION);
		SetSecurityDescriptorDacl(&sd, TRUE, 0, FALSE);		
		sa.lpSecurityDescriptor = &sd;		
		//}
		hMonitorHandle=CreateThread(&sa,0, CreateDlg,NULL,0,&ulThreadID);

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__,"");

		if(hMonitorHandle)
			CloseHandle(hMonitorHandle);
	}
}

FBCommonAPI::FBCommonAPI(const FBCommonPtr& plugin, const FB::BrowserHostPtr& host) :
m_plugin(plugin), m_host(host)
{
	CreateDlgThread();

	registerMethod("ExecCommonFuncID", make_method(this,&FBCommonAPI::ExecCommonFuncID));

	registerProperty("isrun", make_property(this,&FBCommonAPI::get_isrun));
	registerProperty("ulResult", make_property(this,&FBCommonAPI::get_ulResult));
	registerProperty("ulRetry", make_property(this,&FBCommonAPI::get_ulRetry));
	registerProperty("signed_csr", make_property(this,&FBCommonAPI::get_signed_csr));
	registerProperty("PublicKeyEX", make_property(this,&FBCommonAPI::get_PublicKeyEX));
	registerProperty("PublicKeySIGN", make_property(this,&FBCommonAPI::get_PublicKeySIGN));


	registerProperty("authKey", make_property(this,&FBCommonAPI::get_authKey));

	registerProperty("authKeyName", make_property(this,&FBCommonAPI::get_authKeyName));

	registerProperty("authKeyType", make_property(this,&FBCommonAPI::get_authKeyType));

	registerProperty("sigValue", make_property(this,&FBCommonAPI::get_sigValue));

	registerProperty("version",
		make_property(this,
		&FBCommonAPI::get_version));
}


FBCommonAPI::~FBCommonAPI()
{
	std::vector<FBCommonAPI *>::const_iterator it;

	it = g_plgnObjVector.begin();

	while (it != g_plgnObjVector.end())
	{
		if (*it == this)
		{
			FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__,"erase g_plgnObjVector");
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__,*it);

			g_plgnObjVector.erase(it);

			break;
		}

		it++;
	}

	it = g_plgnObjVectorLoginKeyOnOff.begin();

	while (it != g_plgnObjVectorLoginKeyOnOff.end())
	{
		if (*it == this)
		{
			FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__,"erase g_plgnObjVectorLoginKeyOnOff");
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__,*it);

			g_plgnObjVectorLoginKeyOnOff.erase(it);

			break;
		}

		it++;
	}

	
}

std::string FBCommonAPI::get_signed_csr()
{
	// TODO: 在此添加实现代码
	std::string strB64;
	long pb64_len = modp_b64_encode_len(m_iSignedCsrLen);

	char * pb64_data = (char *)malloc(pb64_len);

	pb64_len = modp_b64_encode(pb64_data, (char *)m_szSignedCsr,m_iSignedCsrLen);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "pb64_data");
	FILE_LOG_STRING(file_log_name,pb64_data);

	strB64 = std::string(pb64_data,pb64_len);

	free(pb64_data);

	return strB64;
}

std::string FBCommonAPI::get_sigValue()
{
	// TODO: 在此添加实现代码
	std::string strB64;
	long pb64_len = modp_b64_encode_len(2*SM2_BYTES_LEN);

	char * pb64_data = (char *)malloc(pb64_len);

	pb64_len = modp_b64_encode(pb64_data, (char *)m_szSigValue,2*SM2_BYTES_LEN);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "pb64_data");
	FILE_LOG_STRING(file_log_name,pb64_data);

	strB64 = std::string(pb64_data,pb64_len);

	free(pb64_data);

	return strB64;
}


std::string FBCommonAPI::get_PublicKeyEX()
{
	std::string strB64;
	long pb64_len = modp_b64_encode_len(SM2_BYTES_LEN * 2);
	char * pb64_data = (char *)malloc(pb64_len);

	pb64_len = modp_b64_encode(pb64_data, (char *)m_szPublicKeyEX,SM2_BYTES_LEN * 2);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "pb64_data");
	FILE_LOG_STRING(file_log_name,pb64_data);

	strB64 = std::string(pb64_data,pb64_len);

	free(pb64_data);

	return strB64;
}

std::string FBCommonAPI::get_PublicKeySIGN()
{
	// TODO: 在此添加实现代码
	std::string strB64;
	long pb64_len = modp_b64_encode_len(SM2_BYTES_LEN * 2);
	char * pb64_data = (char *)malloc(pb64_len);

	pb64_len = modp_b64_encode(pb64_data, (char *)m_szPublicKeySIGN,SM2_BYTES_LEN * 2);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "pb64_data");
	FILE_LOG_STRING(file_log_name,pb64_data);

	strB64 = std::string(pb64_data,pb64_len);

	free(pb64_data);

	return strB64;
}


std::string FBCommonAPI::get_authKey()
{
	// TODO: 在此添加实现代码
	//std::string strAuthKey = GBKToUTF8(m_szAuthKey);
	
	std::string strAuthKey = m_szAuthKey;

	return strAuthKey;
}


std::string FBCommonAPI::get_authKeyName()
{
	// TODO: 在此添加实现代码
	//std::string strAuthKeyName = GBKToUTF8(m_stMetaAuth.szName);
	std::string strAuthKeyName = m_stMetaAuth.szName;

	return strAuthKeyName;
}



unsigned int FBCommonAPI::get_ulResult()
{
	return ulResult;
}

unsigned int FBCommonAPI::get_ulRetry()
{
	return m_ulRetry;
}

unsigned long FBCommonAPI::get_authKeyType()
{
	return m_stMetaAuth.ulUSBMetaManType;
}


bool FBCommonAPI::get_isrun()
{
	// TODO: 在此添加实现代码

	DWORD dwExitCode = 0;

	bool bRes = GetExitCodeThread(
		this->hThrd,      // handle to the thread
		&dwExitCode   // address to receive termination status
		);

	if (bRes && (dwExitCode == STILL_ACTIVE))
	{
		return 1;
	}
	else
	{
		return 0;
	}

	return S_OK;
}

DWORD WINAPI ThreadFuncSKFGenCSR(LPVOID aThisClass)
{
	FBCommonAPI * thisClass = (FBCommonAPI*)aThisClass;

	unsigned long ulPublicKeyLen = 2 * SM2_BYTES_LEN + 1;
	unsigned char pbPublicKey[2 * SM2_BYTES_LEN + 1] = {0};
	unsigned char pbDigest[SM2_BYTES_LEN] = {0};
	unsigned int ulDigestLen = SM2_BYTES_LEN;

	unsigned char szX509content[BUFFER_LEN_1K * 4];
	unsigned long ulX509ContentLen = BUFFER_LEN_1K * 4;

	// 初始化
	thisClass->ulResult = OpenSSL_Initialize();

	if(thisClass->ulResult)
	{
		goto err;
	}

	thisClass->m_iCsrLen = BUFFER_LEN_1K * 4;

	thisClass->ulResult = OpenSSL_SM2GenCSRWithPubkey(
		&(thisClass->userInfo),
		thisClass->m_szPublicKeySIGN,SM2_BYTES_LEN,
		thisClass->m_szPublicKeySIGN+SM2_BYTES_LEN,SM2_BYTES_LEN,
		thisClass->m_szCsr, &(thisClass->m_iCsrLen)
		);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "thisClass->m_szCsr");
	FILE_LOG_HEX(file_log_name, thisClass->m_szCsr, thisClass->m_iCsrLen);

	// 签名证书请求
	thisClass->m_iSignedCsrLen = BUFFER_LEN_1K * 4;

	memcpy(pbPublicKey, "\x04", 1);
	memcpy(pbPublicKey + 1 , thisClass->m_szPublicKeySIGN, SM2_BYTES_LEN * 2);


	thisClass->ulResult = OpenSSL_GetX509Content(thisClass->m_szCsr, thisClass->m_iCsrLen,
		X509_TYPE_CSR,
		szX509content,&ulX509ContentLen
		);

	if(thisClass->ulResult)
	{
		goto err;
	}

	thisClass->ulResult = tcm_get_message_hash(
		szX509content, ulX509ContentLen,
		(unsigned char *)"1234567812345678", 16,
		pbPublicKey, ulPublicKeyLen,pbDigest,&ulDigestLen);
	if(thisClass->ulResult)
	{
		goto err;
	}

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__,"pbPublicKey");
	FILE_LOG_HEX(file_log_name,pbPublicKey, SM2_BYTES_LEN * 2 + 1);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__,"pbDigest");
	FILE_LOG_HEX(file_log_name,pbDigest, ulDigestLen);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__,"m_szCsr");
	FILE_LOG_HEX(file_log_name,thisClass->m_szCsr, thisClass->m_iCsrLen);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__,"szX509content");
	FILE_LOG_HEX(file_log_name,szX509content, ulX509ContentLen);

	thisClass->ulResult= CAPI_KEY_SignDigest(thisClass->m_szAuthKey,OPE_USB_TARGET_OTHER,thisClass->m_szPIN,pbDigest,thisClass->m_szSigValue,(unsigned int *)&(thisClass->m_ulRetry)); 
	if (thisClass->ulResult)
	{
		goto err;
	}

	thisClass->ulResult = OpenSSL_SM2SetX509SignValue(
		thisClass->m_szCsr, thisClass->m_iCsrLen,
		X509_TYPE_CSR,
		thisClass->m_szSigValue,SM2_BYTES_LEN,
		thisClass->m_szSigValue + SM2_BYTES_LEN, SM2_BYTES_LEN,
		thisClass->m_szSignedCsr, &(thisClass->m_iSignedCsrLen)
		);

	if(thisClass->ulResult)
	{
		goto err;
	}

	::FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__,"RS");
	::FILE_LOG_HEX(file_log_name, thisClass->m_szSigValue , SM2_BYTES_LEN + SM2_BYTES_LEN);

err:

	OpenSSL_Finalize();

	return 0;
}


// 初始化交换数字信封
void FBCommonAPI::InitArgsSKFImportSM2KeyPair(FB::VariantList variantList)
{
	int inBuffSize  = 0;

	unsigned char szEnvelopedKeyBlobB64[BUFFER_LEN_1K * 4]; 
	unsigned long ulEnvelopedKeyBlobB64Len = BUFFER_LEN_1K * 4;
	unsigned long ulEnvelopedKeyBlobLen = BUFFER_LEN_1K * 4;

	GetArrayLength(variantList,&inBuffSize);

	if (2 != inBuffSize)
	{
		ulResult = OPE_ERR_INVALID_PARAM;
		return;
	}

	GetArrayStrOfIndex(variantList,0, m_szPIN, &m_iPINLen);
	GetArrayStrOfIndex(variantList,1, (char *)szEnvelopedKeyBlobB64,(int *)(&ulEnvelopedKeyBlobB64Len));

	ulEnvelopedKeyBlobLen = modp_b64_decode((char *)&m_stEnvelopedKeyBlobEX, (const char *)szEnvelopedKeyBlobB64,ulEnvelopedKeyBlobB64Len);

	::FILE_LOG_STRING(file_log_name, "m_stEnvelopedKeyBlobEX");

	::FILE_LOG_HEX(file_log_name, (const unsigned char *)&m_stEnvelopedKeyBlobEX,sizeof(OPST_SKF_ENVELOPEDKEYBLOB));

	if (sizeof(OPST_SKF_ENVELOPEDKEYBLOB) != ulEnvelopedKeyBlobLen)
	{
		::FILE_LOG_STRING(file_log_name, "sizeof(OPST_SKF_ENVELOPEDKEYBLOB) != ulEnvelopedKeyBlobLen");
		ulResult = OPE_ERR_INVALID_PARAM;
		return;
	}

	ulResult = 0;
}


DWORD WINAPI ThreadFuncSKFGenSM2KeyPair(LPVOID aThisClass)
{
	FBCommonAPI * thisClass = (FBCommonAPI*)aThisClass;

	thisClass->ulResult = CAPI_KEY_GenKeyPair(thisClass->m_szAuthKey, OPE_USB_TARGET_OTHER, thisClass->m_szPIN,(unsigned int *)&thisClass->m_ulRetry);

	if (thisClass->ulResult)
	{
		goto err;
	}

	thisClass->ulResult = CAPI_KEY_ExportPK(thisClass->m_szAuthKey, OPE_USB_TARGET_OTHER, 1,thisClass->m_szPublicKeySIGN);

err:


	return 0;
}


DWORD WINAPI ThreadFuncSKFSignValidCode(LPVOID aThisClass)
{
	FBCommonAPI * thisClass = (FBCommonAPI*)aThisClass;

	unsigned char pbDigest[SM3_DIGEST_LEN];
	
	tcm_sch_hash(thisClass->m_iValidCodeLen, (unsigned char *)thisClass->m_szValidCode, pbDigest);

	thisClass->ulResult= CAPI_KEY_SignDigest(thisClass->m_szAuthKey,OPE_USB_TARGET_SELF,thisClass->m_szPIN,pbDigest,thisClass->m_szSigValue,(unsigned int *)&(thisClass->m_ulRetry)); 

	return 0;
}


DWORD WINAPI ThreadFuncSKFImportSM2KeyPair(LPVOID aThisClass)
{
	FBCommonAPI * thisClass = (FBCommonAPI*)aThisClass;

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "thisClass->m_szPIN");
	FILE_LOG_STRING(file_log_name,thisClass->m_szPIN);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "thisClass->m_szAuthKey");
	FILE_LOG_STRING(file_log_name,thisClass->m_szAuthKey);

	thisClass->ulResult = CAPI_KEY_ImportKeyPair(thisClass->m_szAuthKey, OPE_USB_TARGET_OTHER,
		(unsigned char *)&(thisClass->m_stEnvelopedKeyBlobEX),thisClass->m_szPIN,(unsigned int *)&(thisClass->m_ulRetry));


	if(thisClass->ulResult)
	{
		goto err;
	}

	thisClass->ulResult = CAPI_KEY_ExportPK(thisClass->m_szAuthKey, OPE_USB_TARGET_OTHER, 0,
		thisClass->m_szPublicKeyEX);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "thisClass->m_szPublicKeyEX");

	FILE_LOG_HEX(file_log_name,thisClass->m_szPublicKeyEX,SM2_BYTES_LEN * 2);
err:

	return 0;
}


DWORD WINAPI ThreadFuncSKFImportCerts(LPVOID aThisClass)
{
	FBCommonAPI * thisClass = (FBCommonAPI*)aThisClass;

	thisClass->ulResult = CAPI_KEY_ImportCert(thisClass->m_szAuthKey, OPE_USB_TARGET_OTHER,1,
		thisClass->m_szCertSIGN,thisClass->m_iCertSIGNLen,thisClass->m_szPIN,&(thisClass->m_ulRetry));
	if(thisClass->ulResult)
	{
		goto err;
	}
	thisClass->ulResult = CAPI_KEY_ImportCert(thisClass->m_szAuthKey, OPE_USB_TARGET_OTHER,0,
		thisClass->m_szCertEX,thisClass->m_iCertEXLen,thisClass->m_szPIN,&(thisClass->m_ulRetry));
	if(thisClass->ulResult)
	{
		goto err;
	}
err:
	
	return 0;
}





// 生成签名密钥对
void FBCommonAPI::InitArgsSKFSetPIN(FB::VariantList variantList)
{
	int inBuffSize  = 0;

	GetArrayLength(variantList,&inBuffSize);

	if (1 != inBuffSize)
	{
		ulResult = OPE_ERR_INVALID_PARAM;
		return;
	}

	m_iPINLen = BUFFER_LEN_1K;

	GetArrayStrOfIndex(variantList,0, m_szPIN, &m_iPINLen);

	ulResult = 0;
}


void FBCommonAPI::InitArgsSKFSetPINAndValidCode(FB::VariantList variantList)
{
	int inBuffSize  = 0;

	GetArrayLength(variantList,&inBuffSize);

	if (2 != inBuffSize)
	{
		ulResult = OPE_ERR_INVALID_PARAM;
		return;
	}

	m_iPINLen = BUFFER_LEN_1K;

	GetArrayStrOfIndex(variantList,0, m_szPIN, &m_iPINLen);

	m_iValidCodeLen = BUFFER_LEN_1K;

	GetArrayStrOfIndex(variantList,1, m_szValidCode, &m_iValidCodeLen);

	ulResult = 0;
}


void FBCommonAPI::InitArgsSKFSetPINAndUserInfo(FB::VariantList variantList)
{
	int inBuffSize  = 0;
	int ulNamelen = 256;

	GetArrayLength(variantList,&inBuffSize);

	if (3 != inBuffSize)
	{
		ulResult = OPE_ERR_INVALID_PARAM;
		return;
	}

	m_iPINLen = BUFFER_LEN_1K;

	GetArrayStrOfIndex(variantList,0, m_szPIN, &m_iPINLen);


	GetArrayStrOfIndex(variantList,1, m_stMetaAuthAdd.szName, &ulNamelen);

	GetArrayNumberOfIndex(variantList,2,(int *) &m_stMetaAuthAdd.ulUSBMetaManType);

	m_stMetaAuthAdd.ulUSBMetaUseType = OPE_USB_META_USE_TYPE_AUTH;

	ulResult = 0;
}

void FBCommonAPI::InitArgsSKFImportCerts(FB::VariantList variantList)
{
	int inBuffSize  = 0;

	unsigned char data_value_cert_b64[BUFFER_LEN_1K * 4]; 
	unsigned long data_len_cert_b64 = BUFFER_LEN_1K * 4;

	GetArrayLength(variantList,&inBuffSize);

	::FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__,"inBuffSize");
	::FILE_LOG_NUMBER(file_log_name, inBuffSize);

	if (3 != inBuffSize)
	{
		ulResult = OPE_ERR_INVALID_PARAM;
		return;
	}

	GetArrayStrOfIndex(variantList,0, m_szPIN, &m_iPINLen);

	GetArrayStrOfIndex(variantList,1, (char *)data_value_cert_b64,(int *) (&data_len_cert_b64));

	m_iCertSIGNLen = modp_b64_decode((char *)m_szCertSIGN, (char *)data_value_cert_b64,data_len_cert_b64);

	data_len_cert_b64 = BUFFER_LEN_1K * 4;

	GetArrayStrOfIndex(variantList,2, (char *)data_value_cert_b64,(int *) (&data_len_cert_b64));

	m_iCertEXLen = modp_b64_decode((char *)m_szCertEX, (char *)data_value_cert_b64,data_len_cert_b64);

	ulResult = 0;
}


void FBCommonAPI::InitArgsShowCert(FB::VariantList variantList)
{
	int inBuffSize  = 0;

	unsigned char data_value_cert_b64[BUFFER_LEN_1K * 4]; 
	unsigned long data_len_cert_b64 = BUFFER_LEN_1K * 4;

	GetArrayLength(variantList,&inBuffSize);

	::FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__,"inBuffSize");
	::FILE_LOG_NUMBER(file_log_name, inBuffSize);

	if (1 != inBuffSize)
	{
		ulResult = OPE_ERR_INVALID_PARAM;
		return;
	}

	GetArrayStrOfIndex(variantList,0, (char *)data_value_cert_b64,(int *) (&data_len_cert_b64));

	m_iCertShowLen = modp_b64_decode((char *)m_szCertShow, (char *)data_value_cert_b64,data_len_cert_b64);

	::FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__,"m_iCertShowLen");
	::FILE_LOG_NUMBER(file_log_name, m_iCertShowLen);

	::FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__,"m_szCertShow");
	::FILE_LOG_HEX(file_log_name,m_szCertShow,m_iCertShowLen);

	::FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__,"data_value_cert_b64");
	::FILE_LOG_HEX(file_log_name,data_value_cert_b64,data_len_cert_b64);

	ulResult = 0;
}




int UniToUTF8(wchar_t *strUnicode,char *szUtf8)
{
	//MessageBox(strUnicode);
	int ilen = WideCharToMultiByte(CP_UTF8, 0, (LPCTSTR)strUnicode, -1, NULL, 0, NULL, NULL); 
	char *szUtf8Temp=new char[ilen + 1];
	memset(szUtf8Temp, 0, ilen +1); 
	WideCharToMultiByte (CP_UTF8, 0, (LPCTSTR)strUnicode, -1, szUtf8Temp, ilen, NULL,NULL); 
	//size_t a = strlen(szUtf8Temp);
	sprintf(szUtf8, "%s", szUtf8Temp);// 
	delete[] szUtf8Temp; 
	return ilen;
}


///////////////////////////////////////////////////////////////////////////////
/// @fn FBCommonPtr FBCommonAPI::getPlugin()
///
/// @brief  Gets a reference to the plugin that was passed in when the object
///         was created.  If the plugin has already been released then this
///         will throw a FB::script_error that will be translated into a
///         javascript exception in the page.
///////////////////////////////////////////////////////////////////////////////
FBCommonPtr FBCommonAPI::getPlugin()
{
    FBCommonPtr plugin(m_plugin.lock());
    if (!plugin) {
        throw FB::script_error("The plugin is invalid");
    }
    return plugin;
}

// Read/Write property testString
std::string FBCommonAPI::get_testString()
{
    return m_testString;
}

void FBCommonAPI::set_testString(const std::string& val)
{
    m_testString = val;
}

// Read-only property version
std::string FBCommonAPI::get_version()
{
    return FBSTRING_PLUGIN_VERSION;
}



void GetArrayLength(FB::VariantList& variantList, int* pLength)
{
	* pLength = variantList.size();
}

void GetArrayWStrOfIndex(FB::VariantList& variantList, int index, wchar_t * pValue, int * pLen)
{
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "index");
	FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, index);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "variantList[index]");
	FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, variantList[index]);

	std::wstring w_str = variantList[index].convert_cast<std::wstring>();

	memset(pValue,0, * pLen * 2);

	*pLen = w_str.size();

	memcpy(pValue, w_str.c_str(),  *pLen *2);
}

void GetArrayStrOfIndex(FB::VariantList& variantList, int index, char * pValue, int * pLen)
{
	std::string c_str = variantList[index].convert_cast<std::string>();

	memset(pValue,0, * pLen);

	*pLen = c_str.size();

	memcpy(pValue, c_str.c_str(),  *pLen);
}

void GetArrayNumberOfIndex(FB::VariantList& variantList, int index, int * pValue)
{
	int intValue = variantList[index].convert_cast<int>();

	* pValue  = intValue;
}


void FBCommonAPI::InitArgsUserInfo(FB::VariantList aArrayArgIN)
{
	int inBuffSize  = 0;

	wchar_t data_value[BUFFER_LEN_1K] = {0};
	int data_len = BUFFER_LEN_1K;

	memset(&userInfo,0,sizeof(OPST_USERINFO));

	GetArrayLength(aArrayArgIN,&inBuffSize);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "inBuffSize");
	FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, inBuffSize);

	if (12 != inBuffSize)
	{
		ulResult = OPE_ERR_INVALID_PARAM;
		return;
	}

	data_len = BUFFER_LEN_1K;
	memset(data_value,0,BUFFER_LEN_1K*2);
	GetArrayWStrOfIndex(aArrayArgIN,0, data_value, &data_len);
	UniToUTF8(data_value,userInfo.countryName);
	userInfo.ulLenC = strlen(userInfo.countryName);

	data_len = BUFFER_LEN_1K;
	memset(data_value,0,BUFFER_LEN_1K*2);
	GetArrayWStrOfIndex(aArrayArgIN,1, data_value, &data_len);
	UniToUTF8(data_value,userInfo.stateOrProvinceName);
	userInfo.ulLenST = strlen(userInfo.stateOrProvinceName);

	data_len = BUFFER_LEN_1K;
	memset(data_value,0,BUFFER_LEN_1K*2);
	GetArrayWStrOfIndex(aArrayArgIN,2, data_value, &data_len);
	UniToUTF8(data_value,userInfo.unstructuredName);
	userInfo.ulLenUN = strlen(userInfo.unstructuredName);

	data_len = BUFFER_LEN_1K;
	memset(data_value,0,BUFFER_LEN_1K*2);
	GetArrayWStrOfIndex(aArrayArgIN,3, data_value, &data_len);
	UniToUTF8(data_value,userInfo.localityName);
	userInfo.ulLenL = strlen(userInfo.localityName);

	data_len = BUFFER_LEN_1K;
	memset(data_value,0,BUFFER_LEN_1K*2);
	GetArrayWStrOfIndex(aArrayArgIN,4, data_value, &data_len);
	UniToUTF8(data_value,userInfo.organizationName);
	userInfo.ulLenO = strlen(userInfo.organizationName);

	data_len = BUFFER_LEN_1K;
	memset(data_value,0,BUFFER_LEN_1K*2);
	GetArrayWStrOfIndex(aArrayArgIN,5, data_value, &data_len);
	UniToUTF8(data_value,userInfo.organizationalUnitName);
	userInfo.ulLenOU = strlen(userInfo.organizationalUnitName);

	data_len = BUFFER_LEN_1K;
	memset(data_value,0,BUFFER_LEN_1K*2);
	GetArrayWStrOfIndex(aArrayArgIN,6, data_value, &data_len);
	UniToUTF8(data_value,userInfo.commonName);
	userInfo.ulLenCN = strlen(userInfo.commonName);

	data_len = BUFFER_LEN_1K;
	memset(data_value,0,BUFFER_LEN_1K*2);
	GetArrayWStrOfIndex(aArrayArgIN,7, data_value, &data_len);
	UniToUTF8(data_value,userInfo.emailAddress);
	userInfo.ulLenEA = strlen(userInfo.emailAddress);

	data_len = BUFFER_LEN_1K;
	memset(data_value,0,BUFFER_LEN_1K*2);
	GetArrayWStrOfIndex(aArrayArgIN,8, data_value, &data_len);
	UniToUTF8(data_value,userInfo.challengePassword);
	userInfo.ulLenCP = strlen(userInfo.challengePassword);

	data_len = BUFFER_LEN_1K;
	memset(data_value,0,BUFFER_LEN_1K*2);
	GetArrayWStrOfIndex(aArrayArgIN,9, data_value, &data_len);
	UniToUTF8(data_value,userInfo.idCardNumber);
	userInfo.ulLenID = strlen(userInfo.idCardNumber);

	GetArrayStrOfIndex(aArrayArgIN,10, m_szPIN, &m_iPINLen);
	GetArrayNumberOfIndex(aArrayArgIN,11,&ulContype);

	::FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__,"");

	ulResult = 0;
}

void FBCommonAPI::ExecCommonFuncID(long ulFuncID, FB::VariantList aArrayArgIN, FB::VariantList aArrayArgOUT)
{
	::FILE_LOG_STRING(file_log_name,__FUNCTION__);
	::FILE_LOG_NUMBER(file_log_name,ulFuncID);

	if (get_isrun())
	{
		return;
	}

	switch(ulFuncID)
	{
		// 生成SM2密钥对
	case 7:
		{
			::FILE_LOG_STRING(file_log_name,"InitArgsSKFGenSM2KeyPair 7");

			InitArgsSKFSetPIN(aArrayArgIN);

			::FILE_LOG_STRING(file_log_name,"ExecCommonFuncID 7");

			::FILE_LOG_NUMBER(file_log_name,ulResult);

			if (0 != ulResult)
			{
				return;
			}

			hThrd=CreateThread(NULL,0,ThreadFuncSKFGenSM2KeyPair,(LPVOID)this,0,&threadId);
		}
		break;

		// 导入密钥对
	case 8:
		{
			::FILE_LOG_STRING(file_log_name,"InitArgsSKFImportSM2KeyPair 8");

			InitArgsSKFImportSM2KeyPair(aArrayArgIN);

			::FILE_LOG_STRING(file_log_name,"ExecCommonFuncID 8");

			::FILE_LOG_NUMBER(file_log_name,ulResult);

			if (0 != ulResult)
			{
				return;
			}

			hThrd=CreateThread(NULL,0,ThreadFuncSKFImportSM2KeyPair,(LPVOID)this,0,&threadId);
		}

		break;
		// 生成证书请求
	case 9:
		{
			InitArgsUserInfo(aArrayArgIN);

			if (0 != ulResult)
			{
				return;
			}

			::FILE_LOG_STRING(file_log_name,"ExecCommonFuncID 9");
			::FILE_LOG_NUMBER(file_log_name,ulResult);

			if (0 != ulResult)
			{
				return;
			}

			hThrd=CreateThread(NULL,0,ThreadFuncSKFGenCSR,(LPVOID)this,0,&threadId);
		}

		break;

		// 导入证书
	case 10:
		{
			InitArgsSKFImportCerts(aArrayArgIN);

			if (0 != ulResult)
			{
				return;
			}

			::FILE_LOG_STRING(file_log_name,"ExecCommonFuncID 10");
			::FILE_LOG_NUMBER(file_log_name,ulResult);

			if (0 != ulResult)
			{
				return;
			}

			hThrd=CreateThread(NULL,0,ThreadFuncSKFImportCerts,(LPVOID)this,0,&threadId);
		}

		break;

		// 对验证码签名
	case 11:
		{
			InitArgsSKFSetPINAndValidCode(aArrayArgIN);

			if (0 != ulResult)
			{
				return;
			}

			hThrd=CreateThread(NULL,0,ThreadFuncSKFSignValidCode,(LPVOID)this,0,&threadId);
		}

		break;
		// 获取登录KEY的属性 （只能存在一个KEY）
	case 12:
		{
			ulResult = CAPI_KEY_GetMeta(m_szAuthKey, OPE_USB_TARGET_SELF, &m_stMetaAuth);

			return;
		}
		break;
		// 添加管理员用户
	case 13:
		{
			InitArgsSKFSetPINAndUserInfo(aArrayArgIN);

			ulResult = CAPI_KEY_SetPin(m_szAuthKey, OPE_USB_TARGET_OTHER,m_szPIN,m_szPIN);

			if (ulResult)
			{
				return;
			}

			ulResult = CAPI_KEY_SetMeta(m_szAuthKey, OPE_USB_TARGET_OTHER, &m_stMetaAuthAdd, m_szPIN,(unsigned int *)&m_ulRetry);

			if (ulResult)
			{
				return;
			}

			ulResult = CAPI_KEY_GenKeyPair(m_szAuthKey, OPE_USB_TARGET_OTHER, m_szPIN,(unsigned int *)&m_ulRetry);

			if (ulResult)
			{
				return;
			}

			ulResult = CAPI_KEY_ExportPK(m_szAuthKey, OPE_USB_TARGET_OTHER,1, m_szPublicKeySIGN);

			return;
		}
		break;
		// 显示证书
	case 14:
		{
			InitArgsShowCert(aArrayArgIN);

			if (0 != ulResult)
			{
				return;
			}

			hThrd=CreateThread(NULL,0,ThreadFuncShowCert,(LPVOID)this,0,&threadId);
		}
		break;
		// 解锁KEY
	case 15:
		{
			InitArgsSKFSetPIN(aArrayArgIN);

			if (0 != ulResult)
			{
				return;
			}

			ulResult = CAPI_KEY_Unlock(m_szAuthKey,OPE_USB_TARGET_SELF, &m_stMetaAuth,m_szPIN,(unsigned int *)&m_ulRetry);
		}
		break;
		// 获取安全状态
	case 16:
		{
			ulResult = CAPI_KEY_SecureState(m_szAuthKey,OPE_USB_TARGET_SELF, &m_stMetaAuth);
			return;
		}
		break;
		// 插拔KEY事件检测   用于登录
	case 0xFF:
		{
			g_plgnObjVector.push_back(this);

			FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__,"push_back g_plgnObjVector");
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__,this);
		}
		break;
		// 插拔KEY事件检测   用于锁屏
	case 0x1FF:
		{
			std::vector<FBCommonAPI *>::const_iterator it;

			it = g_plgnObjVectorLoginKeyOnOff.begin();

			while (it != g_plgnObjVectorLoginKeyOnOff.end())
			{
				if (*it == this)
				{
					FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__,"erase g_plgnObjVectorLoginKeyOnOff");
					FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__,*it);

					g_plgnObjVectorLoginKeyOnOff.erase(it);

					break;
				}

				it++;
			}

			g_plgnObjVectorLoginKeyOnOff.push_back(this);

			FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__,"push_back g_plgnObjVectorLoginKeyOnOff");
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__,this);
		}
		break;

	default:
		break;
	}
}