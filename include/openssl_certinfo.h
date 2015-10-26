

#ifndef __OPENSSL_CERT_PRASE__
#define __OPENSSL_CERT_PRASE__

#include "common.h"


typedef enum ECERT_INFO
{
	ECERT_INFO_VERSION,			// 版本
	ECERT_INFO_SN,				// 序列号
	ECERT_INFO_ISSUER,			// 颁发者
	ECERT_INFO_NOTBEFORE,		// 有效期从
	ECERT_INFO_NOTAFTER,		// 有效期到
	ECERT_INFO_NAME,			// 使用者
	ECERT_INFO_PUBKEY,			// 公钥
	ECERT_INFO_SIG_ALG,			// 签名算法
	ECERT_INFO_KEYUSAGE,		// 密钥用法
	ECERT_INFO_PURPOSE,			// 证书目的

	ECERT_INFO_EXTENSION,       // 扩展信息
	ECERT_INFO_SIG,				// 签名值
	ECERT_INFO_SIG_INNER,		// 签名值(内)
};

typedef enum ECERT_INFO_SUB
{
	//子项定义，iSubNameID
	NID_COMMONNAME				=13	,	//"commonName""CN"
	NID_COUNTRYNAME				=14	,	//"countryName" "C"
	NID_LOCALITYNAME			=15	,	//"localityName" "L"
	NID_STATEORPROVINCENAME		=16	,	//"stateOrProvinceName" "ST"
	NID_ORGANIZATIONNAME		=17	,	//"organizationName" "O"
	NID_ORGANIZATIONALUNITNAME	=18	,	//"organizationalUnitName" "OU"
	NID_PKCS9_EMAILADDRESS		=48	,	//"emailAddress" "E"
};


#ifdef __cplusplus
extern "C" {
#endif
	/*
	功能：设置证书,支持PEM以及DER格式
	参数：data_value_cert：	证书内容
		  data_len_cert：		证书内容长度
	*/
	int COMMON_API OpenSSL_PraseCertInitialize(const unsigned char * pbX509Cert, unsigned long ulX509CertLen);

	//功能：获取证书信息
	//参数：iNameID：	证书信息项，见上宏定义CERT_XXXX
	//	    iSubNameID：证书信息子项，当iNameID=CERT_ISSUER_DN或CERT_SUBJECT_DN时本参数有效, 否则默认为-1, 
	//					本参数有效时，可取值见上宏定义NID_XXX。
	//		pszGB：		返回字符串，  当iNameID=CERT_ISSUER_DN或CERT_SUBJECT_DN时，字符串以"/"作为分隔符。
	//		piLen：		返回字符串长度，当值pszGB为NULL时，本参数可以返回需要的缓存长度。
	//备注：必须预先调用WT_SetMyCert
	int COMMON_API OpenSSL_PraseCertInfo(int iNameID, int iSubNameID, char *pszGB, int* piLen);

	//功能：清除以前设置的证书
	int COMMON_API OpenSSL_PraseCertFinalize();


#ifdef __cplusplus
}
#endif


#endif