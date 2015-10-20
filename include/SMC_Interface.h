#ifndef _SMC_INTERFACE_H
#define _SMC_INTERFACE_H

#include <tchar.h>
#include <windows.h>

// export
#ifdef _WINDOWS
#ifdef DLL_EXPORTS
#define COMMON_API __declspec(dllexport)
#else
#define COMMON_API 
#endif
#else
#define COMMON_API 
#endif

#define DEFAULT_SMC_STORE_SM2_ROOT_ID 1
#define DEFAULT_SMC_STORE_SM2_USER_ID 2
#define DEFAULT_SMC_STORE_SM2_OTHERS_ID 3
#define DEFAULT_SMC_STORE_SM2_CRL_ID 4


typedef enum _EErr_SMC
{
	EErr_SMC_OK,									// 成功
	// SKFERROR 0x0A000001-0x0A000032				// SKF错误码范围
	// HRESULT  0x00000000-0x00015301				// 微软错误码范围
	// HRESULT  0x8000FFFF-0x802A010A				// 微软错误码范围
	// HRESULT  .....								// 微软错误码范围

	 
	EErr_SMC_BASE = 0xF000FFFF,						// 起始错误码
	EErr_SMC_DLL_REG_PATH,							// 注册路径
	EErr_SMC_DLL_PATH,								// 获取函数地址失败
	EErr_SMC_NO_APP,								// 没有应用
	EErr_SMC_CREATE_STORE,							// 创建存储区失败
	EErr_SMC_OPEN_STORE,							// 打开存储区失败
	EErr_SMC_NO_CERT_CHAIN,							// 没有证书链
	EErr_SMC_EXPORT_PUK,							// 导出公钥失败
	EErr_SMC_VERIFY_CERT,							// 验证证书签名失败
	EErr_SMC_VERIFY_TIME,							// 验证证书有效期失败
	EErr_SMC_CREATE_CERT_CONTEXT,					// 创建证书上下文
	EErr_SMC_ADD_CERT_TO_STORE,						// 保存证书
	EErr_SMC_NO_RIGHT,								// 没有权限
	EErr_SMC_SET_CERT_CONTEXT_PROPERTY,				// 设置属性
	EErr_SMC_INVALIDARG,                            // 参数错误
	EErr_SMC_FAIL = -1,

}EErr_SMC;


//#define CERT_FIRST_USER_PROP_ID             0x00008000
//#define CERT_LAST_USER_PROP_ID              0x0000FFFF
// 用户私有ID
#define CERT_DESC_PROP_ID 0x0000FFEE

typedef int BOOL;

// 用户私有ID对应证书属性描述
typedef struct _SK_CERT_DESC_PROPERTY
{
	char szSKFName[64];				// SKF接口名称
	char szDeviceName[256];			// 设备名称
	char szApplicationName[64];		// 应用名称
	char szContainerName[64];		// 容器名称
	char szCommonName[64];			// 通用名 显示设备名
	unsigned int nType;				// 证书类型 WTF_CERT_ALG_FLAG
	BOOL bSignType;					// 签名加密
	unsigned int ulVerify;			// 验证结果 WTF_CERT_VERIFY_RESULT_FLAG
	unsigned long long ulNotBefore;	// 时间
	unsigned long long ulNotAfter;	// 时间
}SK_CERT_DESC_PROPERTY;


#ifdef __cplusplus
extern "C" {
#endif

/*
说明：建立四个证书存储区：
			SM2_ROOT
			SM2_USER
			SM2_OTHERS
			SM2_CRL
备注：内部接口。
*/
COMMON_API BOOL WINAPI SMC_CertCreateSMCStores();

/*
说明：删除指定存储区
备注：内部接口。
*/
COMMON_API BOOL SMC_CertDropSMCStore(_In_ unsigned int uiStoreID);

/*
说明：打开存储区
		uiMsgAndCertEncodingType:	使用0
		uiFlags						使用CERT_SYSTEM_STORE_CURRENT_USER
		uiStoreID ：
			DEFAULT_SMC_STORE_SM2_ROOT_ID 1
			DEFAULT_SMC_STORE_SM2_USER_ID 2
			DEFAULT_SMC_STORE_SM2_OTHERS_ID 3
			DEFAULT_SMC_STORE_SM2_CRL_ID 4
*/
COMMON_API HCERTSTORE WINAPI SMC_CertOpenStore(
	_In_  unsigned int uiMsgAndCertEncodingType,
	_In_  unsigned int uiFlags,
	_In_  unsigned int uiStoreID
	);

/*
说明：关闭存储区
	hCertStore			证书存储区句柄(SMC_CertOpenStore返回)
	uiFlags				使用CERT_CLOSE_STORE_CHECK_FLAG
*/
COMMON_API BOOL WINAPI SMC_CertCloseStore(
	_In_  HCERTSTORE hCertStore,
	_In_  unsigned int uiFlags
	);
/*
说明：把证书加到存储区
	hCertStore			证书存储区句柄(SMC_CertOpenStore返回)
	pCertContext		证书上下文指针(SMC_CertEnumCertificatesInStore,SMC_CertFindCertificateInStore,SMC_CertCreateCertificateContext等返回)
	uiAddDisposition	使用CERT_STORE_ADD_REPLACE_EXISTING
*/
COMMON_API BOOL WINAPI SMC_CertAddCertificateContextToStore(
	_In_       HCERTSTORE hCertStore,
	_In_       PCCERT_CONTEXT pCertContext,
	_In_       unsigned int uiAddDisposition
	);
/*
说明：从存储区删除证书
	pCertContext		证书上下文指针(SMC_CertEnumCertificatesInStore,SMC_CertFindCertificateInStore等返回)
*/
COMMON_API BOOL WINAPI SMC_CertDeleteCertificateFromStore(
	_In_  PCCERT_CONTEXT pCertContext
	);

/*
说明：枚举容器中证书
	hCertStore			证书存储区句柄(SMC_CertOpenStore返回)
	pPrevCertContext	上一个找到的证书指针 (第一次必须填空)
*/
COMMON_API PCCERT_CONTEXT WINAPI SMC_CertEnumCertificatesInStore(
	_In_  HCERTSTORE hCertStore,
	_In_  PCCERT_CONTEXT pPrevCertContext
	);

/*
说明：查找容器中证书
	hCertStore			证书存储区句柄(SMC_CertOpenStore返回)

	uiCertEncodingType	使用X509_ASN_ENCODING

	Value
	CERT_FIND_ANY 
	Data type of pvFindPara: NULL, not used.
	No search criteria used. Returns the next certificate in the store.
	Note  The order of the certificate context may not be preserved within the store. To access a specific certificate you must iterate across the certificates in the store.

	CERT_FIND_CERT_ID 
	Data type of pvFindPara: CERT_ID structure.
	Find the certificate identified by the specified CERT_ID.

	CERT_FIND_ENHKEY_USAGE 
	Data type of pvFindPara: CERT_ENHKEY_USAGE structure.
	Searches for a certificate in the store that has either an enhanced key usage extension or an enhanced key usage property and a usage identifier that matches the cUsageIdentifier member in the  CERT_ENHKEY_USAGE structure.
	A certificate has an enhanced key usage extension if it has a CERT_EXTENSION structure with the pszObjId member set to szOID_ENHANCED_KEY_USAGE.
	A certificate has an enhanced key usage property if its CERT_ENHKEY_USAGE_PROP_ID identifier is set.
	If CERT_FIND_OPTIONAL_ENHKEY_USAGE_FLAG is set in uiFindFlags, certificates without the key usage extension or property are also matches. Setting this flag takes precedence over passing NULL in pvFindPara.
	If CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG is set, a match is done only on the key usage extension.
	For information about flag modifications to search criteria, see Remarks.

	CERT_FIND_EXISTING 
	Data type of pvFindPara: CERT_CONTEXT structure.
	Searches for a certificate that is an exact match of the specified certificate context.

	CERT_FIND_ISSUER_NAME 
	Data type of pvFindPara: CERT_NAME_BLOB structure.
	Search for a certificate with an exact match of the entire issuer name with the name in CERT_NAME_BLOB The search is restricted to certificates that match the uiCertEncodingType.

	CERT_FIND_ISSUER_OF 
	Data type of pvFindPara: CERT_CONTEXT structure.
	Searches for a certificate with an subject that matches the issuer in CERT_CONTEXT.
	Instead of using CertFindCertificateInStore with this value, use the CertGetCertificateChain function.

	CERT_FIND_ISSUER_STR 
	Data type of pvFindPara: Null-terminated Unicode string.
	Searches for a certificate that contains the specified issuer name string. The certificate's issuer member is converted to a name string of the appropriate type using the appropriate form of CertNameToStr formatted as CERT_SIMPLE_NAME_STR. Then a case-insensitive substring-within-a-string match is performed. When this value is set, the search is restricted to certificates whose encoding type matches uiCertEncodingType.
	If the substring match fails and the subject contains an email RDN with Punycode encoded string, CERT_NAME_STR_ENABLE_PUNYCODE_FLAG is used to convert the subject to a Unicode string and the substring match is performed again. 

	CERT_FIND_KEY_IDENTIFIER 
	Data type of pvFindPara: CRYPT_HASH_BLOB structure.
	Searches for a certificate with a CERT_KEY_IDENTIFIER_PROP_ID property that matches the key identifier in CRYPT_HASH_BLOB.

	CERT_FIND_KEY_SPEC 
	Data type of pvFindPara: unsigned int variable that contains a key specification.
	Searches for a certificate that has a CERT_KEY_SPEC_PROP_ID property that matches the key specification in pvFindPara.


	CERT_FIND_PROPERTY 
	Data type of pvFindPara: unsigned int variable that contains a property identifier.
	Searches for a certificate with a property that matches the property identifier specified by the unsigned int value in pvFindPara.

	CERT_FIND_PUBLIC_KEY 
	Data type of pvFindPara: CERT_PUBLIC_KEY_INFO structure.
	Searches for a certificate with a public key that matches the public key in the CERT_PUBLIC_KEY_INFO structure.

	CERT_FIND_SUBJECT_CERT 
	Data type of pvFindPara: CERT_INFO structure.
	Searches for a certificate with both an issuer and a serial number that match the issuer and serial number in the CERT_INFO structure.

	CERT_FIND_SUBJECT_NAME 
	Data type of pvFindPara: CERT_NAME_BLOB structure.
	Searches for a certificate with an exact match of the entire subject name with the name in the CERT_NAME_BLOB structure. The search is restricted to certificates that match the value of uiCertEncodingType.

	CERT_FIND_SUBJECT_STR 
	Data type of pvFindPara: Null-terminated Unicode string.
	Searches for a certificate that contains the specified subject name string. The certificate's subject member is converted to a name string of the appropriate type using the appropriate form of CertNameToStr formatted as CERT_SIMPLE_NAME_STR. Then a case-insensitive substring-within-a-string match is performed. When this value is set, the search is restricted to certificates whose encoding type matches uiCertEncodingType.

	pPrevCertContext	上一个找到的证书指针 (第一次必须填空)
*/
COMMON_API PCCERT_CONTEXT WINAPI SMC_CertFindCertificateInStore(
	_In_  HCERTSTORE hCertStore,
	_In_  unsigned int uiCertEncodingType,
	_In_  unsigned int uiFindType,
	_In_  const void *pvFindPara,
	_In_  PCCERT_CONTEXT pPrevCertContext
	);

/*
说明：设置属性
	pCertContext	证书上下文指针(SMC_CertEnumCertificatesInStore,SMC_CertFindCertificateInStore,SMC_CertCreateCertificateContext等返回)
	uiPropId		CERT_DESC_PROP_ID 自定义ID pvData 为 SK_CERT_DESC_PROPERTY指针
	uiFlags			为CERT_STORE_NO_CRYPT_RELEASE_FLAG
*/

COMMON_API BOOL WINAPI SMC_CertSetCertificateContextProperty(
	_In_  PCCERT_CONTEXT pCertContext,
	_In_  unsigned int uiPropId,
	_In_  unsigned int uiFlags,
	_In_  const void *pvData
	);
/*
说明：获取属性
	pCertContext	证书上下文指针(SMC_CertEnumCertificatesInStore,SMC_CertFindCertificateInStore,SMC_CertCreateCertificateContext等返回)
	uiPropId		CERT_DESC_PROP_ID 自定义ID  pvData 为 SK_CERT_DESC_PROPERTY指针
*/	
COMMON_API BOOL WINAPI SMC_CertGetCertificateContextProperty(
	_In_     PCCERT_CONTEXT pCertContext,
	_In_     unsigned int uiPropId,
	_Out_    void *pvData,
	_Inout_  unsigned int *pcbData
	);

/*
说明：公钥验证证书
	pbCertEncoded	证书内容
	cbCertEncoded	证书内容长度
	pPubKeyInfo		颁发者公钥信息(SMC_CertExportPublicKeyInfo的输出参数)
*/
COMMON_API BOOL WINAPI SMC_CertVerifyCertificateSignature(
	_In_  BYTE *pbCertEncoded,
	_In_  unsigned int cbCertEncoded,
	_In_  PCERT_PUBLIC_KEY_INFO pPubKeyInfo
	);


/*
说明：导出公钥
	pCertContext	证书上下文指针(SMC_CertEnumCertificatesInStore,SMC_CertFindCertificateInStore,SMC_CertCreateCertificateContext等返回)
	pPubKeyInfo		证书公钥信息内容
	pcbPubKeyInfo	证书公钥信息长度
*/
COMMON_API BOOL WINAPI SMC_CertExportPublicKeyInfo(
	_In_     PCCERT_CONTEXT pCertContext,
	_Out_    PCERT_PUBLIC_KEY_INFO pPubKeyInfo,
	_Inout_  unsigned int *pcbPubKeyInfo
	);

/*
说明：验证是否在有效期
	pTimeToVerify	指定一个时间（如果填NULL这表示当前系统时间）
	pCertInfo		PCCERT_CONTEXT的成员pCertInfo
*/
COMMON_API LONG WINAPI SMC_CertVerifyTimeValidity(
	_In_  LPFILETIME pTimeToVerify,
	_In_  PCERT_INFO pCertInfo
	);

/*
说明：创建证书上下文
	uiCertEncodingType		使用X509_ASN_ENCODING
	pbCertEncoded			证书内容
	cbCertEncoded			证书内容长度
*/
COMMON_API PCCERT_CONTEXT WINAPI SMC_CertCreateCertificateContext(
	__in unsigned int uiCertEncodingType,
	__in const BYTE *pbCertEncoded,
	__in unsigned int cbCertEncoded	
	);

/*
说明：释放证书上下文
	pCertContext	证书上下文指针(SMC_CertEnumCertificatesInStore,SMC_CertFindCertificateInStore,SMC_CertCreateCertificateContext等返回)
*/

COMMON_API BOOL WINAPI SMC_CertFreeCertificateContext(
	__in_opt PCCERT_CONTEXT pCertContext	
	);

/*
说明：导入用户证书
	pbCert		证书内容
	ulCertLen	证书长度
	pCertProperty	证书属性(保存硬件相关信息)
返回值: 错误码 EErrCommonAPI_CMBC
*/
COMMON_API unsigned long WINAPI SMC_ImportUserCert(
	BYTE * pbCert, 
	unsigned long ulCertLen, 
	SK_CERT_DESC_PROPERTY * pCertProperty
	);

#ifdef __cplusplus
}
#endif


#endif /*END _SMC_INTERFACE_H*/



