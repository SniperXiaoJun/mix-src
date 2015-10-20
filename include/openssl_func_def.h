
#ifndef _OPENSSL_FUNC_DEF_H_
#define _OPENSSL_FUNC_DEF_H_

#include "o_all_type_def.h"

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif
	/*
	功能名称:	初始化资源
	函数名称:	OpenSSL_Initialize
	输入参数:	
	输出参数:	
	返回值:   
	失败：
	功能描述:	初始化OPENSSL
	*/
	COMMON_API unsigned long OpenSSL_Initialize();

	/*
	功能名称:	释放资源
	函数名称:	OpenSSL_Finalize
	输入参数:	
	输出参数:	
	返回值:   
	失败：
	功能描述:	释放资源
	*/
	COMMON_API unsigned long OpenSSL_Finalize();

	/*
	功能名称:	生成公私钥对
	函数名称:	OpenSSL_SM2GenKeys
	输入参数:	 
	输出参数:	pbPublicKeyX		公钥X
				pbPublicKeyY		公钥Y
				pbPrivateKey		私钥
	返回值:   
	失败：
	功能描述:	生成公私钥对
	*/
	COMMON_API unsigned long OpenSSL_SM2GenKeys(unsigned char * pbPublicKeyX,  unsigned long * pulPublicKeyXLen, 
		unsigned char * pbPublicKeyY,  unsigned long * pulPublicKeyYLen,
		unsigned char * pbPrivateKey,  unsigned long * pulPrivateKeyLen);


	/*
	功能名称:	生成证书请求
	函数名称:	OpenSSL_SM2GenCSRWithPubkey
	输入参数:	pbPublicKeyX     公钥X值
				ulPublicKeyXLen		公钥X长度
				pbPublicKeyY     公钥Y值
				ulPublicKeyYLen		公钥Y长度
	输出参数:	pbCSR		证书请求内容
				pulCSRLen		证书请求长度
	返回值:   
	失败：
	功能描述:	生成证书请求
	*/
	COMMON_API unsigned long OpenSSL_SM2GenCSRWithPubkey(const OPST_USERINFO *pstUserInfo,
		const unsigned char * pbPublicKeyX,  unsigned long ulPublicKeyXLen, 
		const unsigned char * pbPublicKeyY,  unsigned long ulPublicKeyYLen,
		unsigned char * pbCSR,  unsigned long * pulCSRLen);

	/*
	功能名称:	生成根证书
	函数名称:	OpenSSL_SM2GenRootCert
	输入参数:	pbCSR		请求信息
				ulCSRLen			请求长度
				ulSerialNumber	序列号
				ulNotBefore		开始时间
				ulNotAfter		结束时间
	输出参数:	pbX509Cert		证书内容
				pulX509CertLen		证书长度
	返回值:   
	失败：
	功能描述:	生成根证书
	*/
	COMMON_API unsigned long OpenSSL_SM2GenRootCert(const unsigned char * pbCSR,unsigned long ulCSRLen, unsigned long ulSerialNumber,
		unsigned long ulNotBefore, unsigned long ulNotAfter, 
		unsigned char * pbX509Cert, unsigned long * pulX509CertLen);

	/*
	功能名称:	生成SM2证书
	函数名称:	OpenSSL_SM2GenCert
	输入参数:	pbCSR		请求内容
				ulCSRLen			请求长度
				ulSerialNumber	序列号
				ulNotBefore		开始时间
				ulNotAfter		结束时间
	输出参数:	pbX509Cert		证书内容
				pulX509CertLen		证书长度
	返回值:   
	失败：
	功能描述:	生成SM2证书
	*/
	COMMON_API unsigned long OpenSSL_SM2GenCert(const unsigned char * pbCSR,unsigned long ulCSRLen, 
		const unsigned char * pbX509CACert, unsigned long ulX509CACertLen, 
		unsigned long ulSerialNumber,
		unsigned long ulNotBefore, unsigned long ulNotAfter, unsigned long ulSignFlag,
		unsigned char * pbX509Cert, unsigned long * pulX509CertLen);
	
	/*
	功能名称:	生成SM2证书(扩展，验证并替换证书请求的公钥之后生成证书)
	函数名称:	OpenSSL_SM2GenCert
	输入参数:	pbCSR		请求内容
				ulCSRLen			请求长度
				ulSerialNumber	序列号
				ulNotBefore		开始时间
				ulNotAfter		结束时间
	输出参数:	pbX509Cert		证书内容
				pulX509CertLen		证书长度
	返回值:   
	失败：
	功能描述:	生成SM2证书
	*/
	COMMON_API unsigned long OpenSSL_SM2GenCertEX(const unsigned char * pbCSR,unsigned long ulCSRLen, 
		const unsigned char * pbPublicKeyX, unsigned long ulPublicKeyXLen, 
		const unsigned char * pbPublicKeyY, unsigned long ulPublicKeyYLen,
		const unsigned char * pbX509CACert, unsigned long ulX509CACertLen, 
		unsigned long ulSerialNumber,
		unsigned long ulNotBefore, unsigned long ulNotAfter, unsigned long ulSignFlag,
		unsigned char * pbX509Cert, unsigned long * pulX509CertLen);

	/*
	功能名称:	证书吊销列表
	函数名称:	OpenSSL_SM2GenCRL
	输入参数:	pstCRLList				证书吊销内容
				ulCRLListSize			证书个数
				pbX509Cert			证书内容
				ulX509CertLen				证书长度
	输出参数:   
				pbCRL				证书吊销列表内容
				pulCRLLen				证书吊销列表长度
	返回值:   
	失败：
	功能描述:	证书吊销列表
	*/
	COMMON_API unsigned long OpenSSL_SM2GenCRL(const OPST_CRL * pstCRLList, unsigned long ulCRLListSize, 
		const unsigned char * pbX509Cert,unsigned long ulX509CertLen, 
		unsigned char * pbCRL, unsigned long * pulCRLLen);

	
	/*
	功能名称:	对证书进行签名
	函数名称:	OpenSSL_SM2SignCertWithKeys
	输入参数:	pbX509Cert					待签名证书内容
				ulX509CertLen				待签名证书长度
				pbPublicKeyX				签名者公钥X
				pbPublicKeyY				签名者公钥Y
				pbPrivateKey				私钥内容
				ulPrivateKeyLen				私钥长度
	输出参数:   pbX509CertSigned				签名证书内容
				pulX509CertSignedLen			签名证书长度
	返回值:   
	失败：
	功能描述:	对证书进行签名
	*/
	COMMON_API unsigned long OpenSSL_SM2SignCert(
		const unsigned char *pbX509Cert,  unsigned long ulX509CertLen, 
		const unsigned char *pbPublicKeyX, unsigned long ulPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned long ulPublicKeyYLen,
		const unsigned char *pbPrivateKey,  unsigned long ulPrivateKeyLen,
		unsigned char * pbX509CertSigned,  unsigned long * pulX509CertSignedLen
		);

	/*
	功能名称:	对证书请求进行签名
	函数名称:	OpenSSL_SM2SignCSR
	输入参数:	pbCSR					待签名证书请求内容
				ulCSRLen					待签名证书请求长度
				pbPrivateKey				私钥内容
				ulPrivateKeyLen				私钥长度
	输出参数:   pbCSRSigned				签名证书请求内容
				pulCSRSignedLen			签名证书请求长度
	返回值:   
	失败：
	功能描述:	对证书请求进行签名
	*/
	COMMON_API unsigned long OpenSSL_SM2SignCSR(
		const unsigned char *pbCSR, unsigned long ulCSRLen,
		const unsigned char * pbPrivateKey,unsigned long ulPrivateKeyLen,
		unsigned long ulAlg,
		unsigned char *pbCSRSigned, unsigned long * pulCSRSignedLen);

	/*
	功能名称:	对CRL进行签名
	函数名称:	OpenSSL_SM2SignCRL
	输入参数:	pbCRL					待签名CRL内容
				ulCRLLen					待签名CRL长度
				pbPublicKeyX				签名者公钥X
				pbPublicKeyY				签名者公钥Y
				pbPrivateKey				私钥内容
				ulPrivateKeyLen				私钥长度
	输出参数:   pbCRLSigned				签名CRL内容
				pulCRLSignedLen			签名CRL长度
	返回值:   
	失败：
	功能描述:	对CRL进行签名
	*/
	COMMON_API unsigned long OpenSSL_SM2SignCRL(
		const unsigned char *pbCRL, unsigned long ulCRLLen,unsigned long ulAlg,
		const unsigned char *pbPublicKeyX, unsigned long ulPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned long ulPublicKeyYLen,
		const unsigned char * pbPrivateKey,unsigned long ulPrivateKeyLen,
		unsigned char *pbCRLSigned, unsigned long * pulCRLSignedLen
		);

	/*
	功能名称:	对消息进行签名
	函数名称:	OpenSSL_SM2SignMSG
	输入参数:	pbMSG						待签名内容
				ulMSGLen					待签名长度
				pbPublicKeyX				签名者公钥X
				pbPublicKeyY				签名者公钥Y
				pbPrivateKey				私钥内容
				ulPrivateKeyLen				私钥长度
	输出参数:   pbCRLSigned				签名CRL内容
				pulCRLSignedLen			签名CRL长度
	返回值:   
	失败：
	功能描述:	对消息进行签名
	*/
	COMMON_API unsigned long OpenSSL_SM2SignMSG(const unsigned char *pbMSG, unsigned long ulMSGLen, 
		const unsigned char *pbPublicKeyX, unsigned long ulPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned long ulPublicKeyYLen,
		const unsigned char * pbPrivateKey,unsigned long ulPrivateKeyLen,
		unsigned long ulAlg,
		unsigned char *pbSig, unsigned long * pulSigLen);
	/*
	功能名称:	对HASH进行签名
	函数名称:	OpenSSL_SM2SignMSG
	输入参数:	pbHash						待签名hash内容
				ulHashLen					待签名hash长度
				pbPublicKeyX				签名者公钥X
				pbPublicKeyY				签名者公钥Y
				pbPrivateKey				私钥内容
				ulPrivateKeyLen				私钥长度
	输出参数:   pbCRLSigned				签名CRL内容
				pulCRLSignedLen			签名CRL长度
	返回值:   
	失败：
	功能描述:	对HASH进行签名
	*/
	COMMON_API unsigned long OpenSSL_SM2SignDigest(const unsigned char *pbHash, unsigned long ulHashLen, 
		const unsigned char *pbPrivateKey, unsigned long ulPrivateKeyLen,
		unsigned char *pbSig, unsigned long * pulSigLen
		);

	//X509结构内容
	typedef enum _X509_TYPE
	{
		X509_TYPE_CSR = 0,
		X509_TYPE_CERT = 1,
		X509_TYPE_CRL=2,
	}X509_TYPE;

	/*
	功能名称:	设置X509内容的签名值
	函数名称:	OpenSSL_SM2SetX509SignValue
	输入参数:	
	输出参数:   
	返回值:   
	失败：
	功能描述:	设置X509内容的签名值
	*/
	COMMON_API unsigned long OpenSSL_SM2SetX509SignValue(
		const unsigned char *pbX509, unsigned long ulX509Len,
		X509_TYPE ulX509Type,
		const unsigned char *pbR, unsigned long ulRLen,
		const unsigned char *pbS, unsigned long ulSLen,
		unsigned char *pbX509Signed, unsigned long * pulX509SignedLen);
	
	/*
	功能名称:	获取X509内容（不包含签名值）
	函数名称:	OpenSSL_SM2SetX509SignValue
	输入参数:	
	输出参数:   
	返回值:   
	失败：
	功能描述:	获取X509内容（不包含签名值）
	*/
	COMMON_API unsigned long OpenSSL_GetX509Content(
		const unsigned char *pbX509, unsigned long ulX509Len,
		X509_TYPE ulX509Type,
		unsigned char *pbX509Content, unsigned long *pulX509ContentLen
		);

	/*
	功能名称:	验证SM2签名
	函数名称:	OpenSSL_SM2VerifyDigest
	输入参数:	pbHash		HASH内容
				ulHashLen			HASH长度
				pbSig			签名内容
				ulSigLen				签名长度
				pbPublicKeyX		公钥X内容
				ulPublicKeyXLen			公钥X长度
				pbPublicKeyY		公钥Y内容
				ulPublicKeyYLen			公钥Y长度
	输出参数:
	返回值:   
	失败：
	功能描述:	验证SM2签名
	*/
	COMMON_API unsigned long OpenSSL_SM2VerifyDigest(const unsigned char *pbHash, unsigned long ulHashLen, 
		const unsigned char *pbSig, unsigned long ulSigLen,
		const unsigned char *pbPublicKeyX, unsigned long ulPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned long ulPublicKeyYLen);

	/*
	功能名称:	验证签名
	函数名称:	OpenSSL_SM2VerifyMSG
	输入参数:	pbMSG				原文内容
				ulMSGLen					原文长度
				pbSig				签名值内容
				ulSigLen					签名值长度
				pbPublicKeyX			公钥X内容
				ulPublicKeyXLen				公钥X长度
				pbPublicKeyY			公钥Y内容
				ulPublicKeyYLen				公钥Y长度
	输出参数:   
	返回值:   
	失败：
	功能描述:	验证签名
	*/
	COMMON_API unsigned long OpenSSL_SM2VerifyMSG(const unsigned char *pbMSG, unsigned long ulMSGLen, 
		const unsigned char *pbSig, unsigned long ulSigLen,
		const unsigned char *pbPublicKeyX, unsigned long ulPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned long ulPublicKeyYLen);

	/*
	功能名称:	验证请求
	函数名称:	OpenSSL_SM2VerifyCSR
	输入参数:	pbIN				请求内容
				ulINLen					请求长度
				pbSig				签名值内容
				ulSigLen					签名值长度
	输出参数:   
	返回值:   
	失败：
	功能描述:	验证请求
	*/
	COMMON_API unsigned long OpenSSL_SM2VerifyCSR(
		const unsigned char *pbCSR, unsigned long ulCSRLen,
		unsigned long ulAlg
		);

	/*
	功能名称:	验证证书
	函数名称:	OpenSSL_SM2VerifyCert
	输入参数:	pbX509Cert			证书内容
				ulX509CertLen				证书长度
				pbPublicKeyX			公钥X内容
				ulPublicKeyXLen				公钥X长度
				pbPublicKeyY			公钥Y内容
				ulPublicKeyYLen				公钥Y长度
	输出参数:   
	返回值:   
	失败：
	功能描述:	验证证书
	*/
	COMMON_API unsigned long OpenSSL_SM2VerifyCert(
		const unsigned char *pbX509Cert, unsigned long ulX509CertLen,unsigned long ulAlg,
		const unsigned char *pbPublicKeyX, unsigned long ulPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned long ulPublicKeyYLen
		);

	/*
	功能名称:	验证CRL
	函数名称:	OpenSSL_SM2VerifyCRL
	输入参数:	pbCRL					CRL内容
				ulCRLLen				CRL长度
				pbPublicKeyX			公钥X内容
				ulPublicKeyXLen			公钥X长度
				pbPublicKeyY			公钥Y内容
				ulPublicKeyYLen			公钥Y长度
	输出参数:   
	返回值:   
	失败：
	功能描述:	验证证书
	*/
	COMMON_API unsigned long OpenSSL_SM2VerifyCRL(
		const unsigned char *pbCRL, unsigned long ulCRLLen,unsigned long ulAlg,
		const unsigned char *pbPublicKeyX, unsigned long ulPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned long ulPublicKeyYLen
		);

	/*
	功能名称:	获取证书主题
	函数名称:	OpenSSL_CertGetSubject
	输入参数:	pbX509Cert		证书内容
				ulX509CertLen		证书长度
	输出参数:	pbSubject	主题内容
				pulSubjectLen		主题长度
	返回值:   
	失败：
	功能描述:	获取证书主题
	*/
	COMMON_API unsigned long OpenSSL_CertGetSubject(
		const unsigned char * pbX509Cert, unsigned long ulX509CertLen,
		unsigned char * pbSubject, unsigned long * pulSubjectLen
		);

	/*
	功能名称:	获取证书公钥
	函数名称:	OpenSSL_CertGetPubkey
	输入参数:	pbX509Cert		证书内容
				ulX509CertLen		证书长度
	输出参数:	pbPublicKey	公钥内容
				pulPublicKeyLen		公钥长度
	返回值:   
	失败：
	功能描述:	获取证书公钥
	*/
	COMMON_API unsigned long OpenSSL_CertGetPubkey(
		const unsigned char * pbX509Cert, unsigned long ulX509CertLen,
		unsigned char * pbPublicKey, unsigned long * pulPublicKeyLen);

	/*
	功能名称:	获取证书主题项
	函数名称:	OpenSSL_CertGetSubjectItem
	输入参数:	
				pbX509Cert				证书内容
				ulX509CertLen			证书长度
				ulIndex					项标示
	输出参数:   
				pbSubjectItem			项值
				pulSubjectItemLen		项长度
	返回值:   
	失败：
	功能描述:	获取证书主题项
	*/
	COMMON_API unsigned long OpenSSL_CertGetSubjectItem(
		const unsigned char * pbX509Cert, unsigned long ulX509CertLen,
		int ulIndex, 
		unsigned char * pbSubjectItem, unsigned long * pulSubjectItemLen
		);

	/*
	功能名称:	SM2解密
	*/
	COMMON_API unsigned long OpenSSL_SM2Decrypt(
		const unsigned char * pbPrivateKey, unsigned long ulPrivateKeyLen, 
		const unsigned char * pbIN, unsigned long ulINLen,
		unsigned char * pbOUT, unsigned long * pulOUTLen
		);
	/*
	功能名称:	SM2加密
	*/
	COMMON_API unsigned long OpenSSL_SM2Encrypt(
		const unsigned char * pbPublicKeyX, unsigned long ulPublicKeyXLen, 
		const unsigned char * pbPublicKeyY, unsigned long ulPublicKeyYLen,
		const unsigned char * pbIN, unsigned long ulINLen,
		unsigned char * pbOUT, unsigned long * pulOUTLen);

	/*
	功能名称:	验证SM2点
	*/
	COMMON_API unsigned long OpenSSL_SM2Point(
		const unsigned char * pbPublicKeyX, unsigned long ulPublicKeyXLen, 
		const unsigned char * pbPublicKeyY, unsigned long ulPublicKeyYLen
		);

	/*
	功能名称:	加密内容输出文件
	*/
	COMMON_API unsigned long OpenSSL_SM2Write(
		const unsigned char * pbIN, unsigned long ulINLen, 
		unsigned long ulType,
		char * szFileName,
		unsigned long fileEncode, char * szPassword
		);

	/*
	功能名称:	SM2解密
	*/
	COMMON_API unsigned long OpenSSL_SM2DecryptInner(
		const unsigned char *pbIN, unsigned long ulINLen, 
		const unsigned char *pbPrivateKey, unsigned long ulPrivateKeyLen, 
		unsigned char *pbOUT, unsigned long * pulOUTLen
		);

	/*
	功能名称:	SM2加密
	*/
	COMMON_API unsigned long OpenSSL_SM2EncryptInner(
		const unsigned char *pbIN, unsigned long ulINLen, 
		const unsigned char *pbPublicKeyX, unsigned long ulPublicKeyXLen, 
		const unsigned char *pbPublicKeyY, unsigned long ulPublicKeyYLen, 
		unsigned char *pbOUT, unsigned long * pulOUTLen
		);

	/*
	功能名称:	获取证书公钥算法
	*/
	COMMON_API unsigned long OpenSSL_CertGetPublicKeyAlgor(
		const unsigned char * pbX509Cert, unsigned long ulX509CertLen,
		unsigned char *pbPublicKeyAlgor, unsigned long *pulPublicKeyAlgorLen
		);

	/*
	功能名称:	比较证书的颁发者和使用者
	*/
	COMMON_API unsigned long OpenSSL_CertSubjectCompareIssuer(const unsigned char * pbX509Cert, unsigned long ulX509CertLen,
		unsigned long * bEqual
		);

	COMMON_API unsigned long OpenSSL_CertExtenItem(const unsigned char * pbX509Cert, unsigned long ulX509CertLen,int ulIndex, unsigned char * pbSubjectItem, unsigned long * pulSubjectItemLen);

#ifdef __cplusplus
}
#endif


#endif /*_OPENSSL_FUNC_DEF_H_*/