
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
	COMMON_API unsigned int OpenSSL_Initialize();

	/*
	功能名称:	释放资源
	函数名称:	OpenSSL_Finalize
	输入参数:	
	输出参数:	
	返回值:   
	失败：
	功能描述:	释放资源
	*/
	COMMON_API unsigned int OpenSSL_Finalize();

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
	COMMON_API unsigned int OpenSSL_SM2GenKeys(unsigned char * pbPublicKeyX,  unsigned int * puiPublicKeyXLen, 
		unsigned char * pbPublicKeyY,  unsigned int * puiPublicKeyYLen,
		unsigned char * pbPrivateKey,  unsigned int * puiPrivateKeyLen);


	/*
	功能名称:	生成证书请求
	函数名称:	OpenSSL_SM2GenCSRWithPubkey
	输入参数:	pbPublicKeyX     公钥X值
				uiPublicKeyXLen		公钥X长度
				pbPublicKeyY     公钥Y值
				uiPublicKeyYLen		公钥Y长度
	输出参数:	pbCSR		证书请求内容
				puiCSRLen		证书请求长度
	返回值:   
	失败：
	功能描述:	生成证书请求
	*/
	COMMON_API unsigned int OpenSSL_SM2GenCSRWithPubkey(const OPST_USERINFO *pstUserInfo,
		const unsigned char * pbPublicKeyX,  unsigned int uiPublicKeyXLen, 
		const unsigned char * pbPublicKeyY,  unsigned int uiPublicKeyYLen,
		unsigned char * pbCSR,  unsigned int * puiCSRLen);

	/*
	功能名称:	生成根证书
	函数名称:	OpenSSL_SM2GenRootCert
	输入参数:	pbCSR		请求信息
				uiCSRLen			请求长度
				uiSerialNumber	序列号
				uiNotBefore		开始时间
				uiNotAfter		结束时间
	输出参数:	pbX509Cert		证书内容
				puiX509CertLen		证书长度
	返回值:   
	失败：
	功能描述:	生成根证书
	*/
	COMMON_API unsigned int OpenSSL_SM2GenRootCert(const unsigned char * pbCSR,unsigned int uiCSRLen, 
		unsigned char * pbSerialNumber,unsigned int uiSerialNumberLen,
		unsigned int uiNotBefore, unsigned int uiNotAfter, 
		unsigned char * pbX509Cert, unsigned int * puiX509CertLen);

	/*
	功能名称:	生成SM2证书
	函数名称:	OpenSSL_SM2GenCert
	输入参数:	pbCSR		请求内容
				uiCSRLen			请求长度
				uiSerialNumber	序列号
				uiNotBefore		开始时间
				uiNotAfter		结束时间
	输出参数:	pbX509Cert		证书内容
				puiX509CertLen		证书长度
	返回值:   
	失败：
	功能描述:	生成SM2证书
	*/
	COMMON_API unsigned int OpenSSL_SM2GenCert(const unsigned char * pbCSR,unsigned int uiCSRLen, 
		const unsigned char * pbX509CACert, unsigned int uiX509CACertLen, 
		unsigned char * pbSerialNumber,unsigned int uiSerialNumberLen,
		unsigned int uiNotBefore, unsigned int uiNotAfter, unsigned int uiSignFlag,
		unsigned char * pbX509Cert, unsigned int * puiX509CertLen);
	
	/*
	功能名称:	生成SM2证书(扩展，验证并替换证书请求的公钥之后生成证书)
	函数名称:	OpenSSL_SM2GenCert
	输入参数:	pbCSR		请求内容
				uiCSRLen			请求长度
				uiSerialNumber	序列号
				uiNotBefore		开始时间
				uiNotAfter		结束时间
	输出参数:	pbX509Cert		证书内容
				puiX509CertLen		证书长度
	返回值:   
	失败：
	功能描述:	生成SM2证书
	*/
	COMMON_API unsigned int OpenSSL_SM2GenCertEX(const unsigned char * pbCSR,unsigned int uiCSRLen, 
		const unsigned char * pbPublicKeyX, unsigned int uiPublicKeyXLen, 
		const unsigned char * pbPublicKeyY, unsigned int uiPublicKeyYLen,
		const unsigned char * pbX509CACert, unsigned int uiX509CACertLen, 
		unsigned char * pbSerialNumber,unsigned int uiSerialNumberLen,
		unsigned int uiNotBefore, unsigned int uiNotAfter, unsigned int uiSignFlag,
		unsigned char * pbX509Cert, unsigned int * puiX509CertLen);

	/*
	功能名称:	证书吊销列表
	函数名称:	OpenSSL_SM2GenCRL
	输入参数:	pstCRLList				证书吊销内容
				uiCRLListSize			证书个数
				pbX509Cert			证书内容
				uiX509CertLen				证书长度
	输出参数:   
				pbCRL				证书吊销列表内容
				puiCRLLen				证书吊销列表长度
	返回值:   
	失败：
	功能描述:	证书吊销列表
	*/
	COMMON_API unsigned int OpenSSL_SM2GenCRL(const OPST_CRL * pstCRLList, unsigned int uiCRLListSize, 
		const unsigned char * pbX509Cert,unsigned int uiX509CertLen, 
		unsigned char * pbCRL, unsigned int * puiCRLLen);

	
	/*
	功能名称:	对证书进行签名
	函数名称:	OpenSSL_SM2SignCertWithKeys
	输入参数:	pbX509Cert					待签名证书内容
				uiX509CertLen				待签名证书长度
				pbPublicKeyX				签名者公钥X
				pbPublicKeyY				签名者公钥Y
				pbPrivateKey				私钥内容
				uiPrivateKeyLen				私钥长度
	输出参数:   pbX509CertSigned				签名证书内容
				puiX509CertSignedLen			签名证书长度
	返回值:   
	失败：
	功能描述:	对证书进行签名
	*/
	COMMON_API unsigned int OpenSSL_SM2SignCert(
		const unsigned char *pbX509Cert,  unsigned int uiX509CertLen, 
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen,
		const unsigned char *pbPrivateKey,  unsigned int uiPrivateKeyLen,
		unsigned char * pbX509CertSigned,  unsigned int * puiX509CertSignedLen
		);

	/*
	功能名称:	对证书请求进行签名
	函数名称:	OpenSSL_SM2SignCSR
	输入参数:	pbCSR					待签名证书请求内容
				uiCSRLen					待签名证书请求长度
				pbPrivateKey				私钥内容
				uiPrivateKeyLen				私钥长度
	输出参数:   pbCSRSigned				签名证书请求内容
				puiCSRSignedLen			签名证书请求长度
	返回值:   
	失败：
	功能描述:	对证书请求进行签名
	*/
	COMMON_API unsigned int OpenSSL_SM2SignCSR(
		const unsigned char *pbCSR, unsigned int uiCSRLen,
		const unsigned char * pbPrivateKey,unsigned int uiPrivateKeyLen,
		unsigned int uiAlg,
		unsigned char *pbCSRSigned, unsigned int * puiCSRSignedLen);

	/*
	功能名称:	对CRL进行签名
	函数名称:	OpenSSL_SM2SignCRL
	输入参数:	pbCRL					待签名CRL内容
				uiCRLLen					待签名CRL长度
				pbPublicKeyX				签名者公钥X
				pbPublicKeyY				签名者公钥Y
				pbPrivateKey				私钥内容
				uiPrivateKeyLen				私钥长度
	输出参数:   pbCRLSigned				签名CRL内容
				puiCRLSignedLen			签名CRL长度
	返回值:   
	失败：
	功能描述:	对CRL进行签名
	*/
	COMMON_API unsigned int OpenSSL_SM2SignCRL(
		const unsigned char *pbCRL, unsigned int uiCRLLen,unsigned int uiAlg,
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen,
		const unsigned char * pbPrivateKey,unsigned int uiPrivateKeyLen,
		unsigned char *pbCRLSigned, unsigned int * puiCRLSignedLen
		);

	/*
	功能名称:	对消息进行签名
	函数名称:	OpenSSL_SM2SignMSG
	输入参数:	pbMSG						待签名内容
				uiMSGLen					待签名长度
				pbPublicKeyX				签名者公钥X
				pbPublicKeyY				签名者公钥Y
				pbPrivateKey				私钥内容
				uiPrivateKeyLen				私钥长度
	输出参数:   pbCRLSigned				签名CRL内容
				puiCRLSignedLen			签名CRL长度
	返回值:   
	失败：
	功能描述:	对消息进行签名
	*/
	COMMON_API unsigned int OpenSSL_SM2SignMSG(const unsigned char *pbMSG, unsigned int uiMSGLen, 
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen,
		const unsigned char * pbPrivateKey,unsigned int uiPrivateKeyLen,
		unsigned int uiAlg,
		unsigned char *pbSig, unsigned int * puiSigLen);
	/*
	功能名称:	对HASH进行签名
	函数名称:	OpenSSL_SM2SignMSG
	输入参数:	pbHash						待签名hash内容
				uiHashLen					待签名hash长度
				pbPublicKeyX				签名者公钥X
				pbPublicKeyY				签名者公钥Y
				pbPrivateKey				私钥内容
				uiPrivateKeyLen				私钥长度
	输出参数:   pbCRLSigned				签名CRL内容
				puiCRLSignedLen			签名CRL长度
	返回值:   
	失败：
	功能描述:	对HASH进行签名
	*/
	COMMON_API unsigned int OpenSSL_SM2SignDigest(const unsigned char *pbHash, unsigned int uiHashLen, 
		const unsigned char *pbPrivateKey, unsigned int uiPrivateKeyLen,
		unsigned char *pbSig, unsigned int * puiSigLen
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
	COMMON_API unsigned int OpenSSL_SM2SetX509SignValue(
		const unsigned char *pbX509, unsigned int uiX509Len,
		X509_TYPE uiX509Type,
		const unsigned char *pbR, unsigned int uiRLen,
		const unsigned char *pbS, unsigned int uiSLen,
		unsigned char *pbX509Signed, unsigned int * puiX509SignedLen);
	
	/*
	功能名称:	获取X509内容（不包含签名值）
	函数名称:	OpenSSL_SM2SetX509SignValue
	输入参数:	
	输出参数:   
	返回值:   
	失败：
	功能描述:	获取X509内容（不包含签名值）
	*/
	COMMON_API unsigned int OpenSSL_GetX509Content(
		const unsigned char *pbX509, unsigned int uiX509Len,
		X509_TYPE uiX509Type,
		unsigned char *pbX509Content, unsigned int *puiX509ContentLen
		);

	/*
	功能名称:	验证SM2签名
	函数名称:	OpenSSL_SM2VerifyDigest
	输入参数:	pbHash		HASH内容
				uiHashLen			HASH长度
				pbSig			签名内容
				uiSigLen				签名长度
				pbPublicKeyX		公钥X内容
				uiPublicKeyXLen			公钥X长度
				pbPublicKeyY		公钥Y内容
				uiPublicKeyYLen			公钥Y长度
	输出参数:
	返回值:   
	失败：
	功能描述:	验证SM2签名
	*/
	COMMON_API unsigned int OpenSSL_SM2VerifyDigest(const unsigned char *pbHash, unsigned int uiHashLen, 
		const unsigned char *pbSig, unsigned int uiSigLen,
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen);

	/*
	功能名称:	验证签名
	函数名称:	OpenSSL_SM2VerifyMSG
	输入参数:	pbMSG				原文内容
				uiMSGLen					原文长度
				pbSig				签名值内容
				uiSigLen					签名值长度
				pbPublicKeyX			公钥X内容
				uiPublicKeyXLen				公钥X长度
				pbPublicKeyY			公钥Y内容
				uiPublicKeyYLen				公钥Y长度
	输出参数:   
	返回值:   
	失败：
	功能描述:	验证签名
	*/
	COMMON_API unsigned int OpenSSL_SM2VerifyMSG(const unsigned char *pbMSG, unsigned int uiMSGLen, 
		const unsigned char *pbSig, unsigned int uiSigLen,
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen);

	/*
	功能名称:	验证请求
	函数名称:	OpenSSL_SM2VerifyCSR
	输入参数:	pbIN				请求内容
				uiINLen					请求长度
				pbSig				签名值内容
				uiSigLen					签名值长度
	输出参数:   
	返回值:   
	失败：
	功能描述:	验证请求
	*/
	COMMON_API unsigned int OpenSSL_SM2VerifyCSR(
		const unsigned char *pbCSR, unsigned int uiCSRLen,
		unsigned int uiAlg
		);

	/*
	功能名称:	验证证书
	函数名称:	OpenSSL_SM2VerifyCert
	输入参数:	pbX509Cert			证书内容
				uiX509CertLen				证书长度
				pbPublicKeyX			公钥X内容
				uiPublicKeyXLen				公钥X长度
				pbPublicKeyY			公钥Y内容
				uiPublicKeyYLen				公钥Y长度
	输出参数:   
	返回值:   
	失败：
	功能描述:	验证证书
	*/
	COMMON_API unsigned int OpenSSL_SM2VerifyCert(
		const unsigned char *pbX509Cert, unsigned int uiX509CertLen,unsigned int uiAlg,
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen
		);

	/*
	功能名称:	验证CRL
	函数名称:	OpenSSL_SM2VerifyCRL
	输入参数:	pbCRL					CRL内容
				uiCRLLen				CRL长度
				pbPublicKeyX			公钥X内容
				uiPublicKeyXLen			公钥X长度
				pbPublicKeyY			公钥Y内容
				uiPublicKeyYLen			公钥Y长度
	输出参数:   
	返回值:   
	失败：
	功能描述:	验证证书
	*/
	COMMON_API unsigned int OpenSSL_SM2VerifyCRL(
		const unsigned char *pbCRL, unsigned int uiCRLLen,unsigned int uiAlg,
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen
		);

	/*
	功能名称:	获取证书主题
	函数名称:	OpenSSL_CertGetSubject
	输入参数:	pbX509Cert		证书内容
				uiX509CertLen		证书长度
	输出参数:	pbSubject	主题内容
				puiSubjectLen		主题长度
	返回值:   
	失败：
	功能描述:	获取证书主题
	*/
	COMMON_API unsigned int OpenSSL_CertGetSubject(
		const unsigned char * pbX509Cert, unsigned int uiX509CertLen,
		unsigned char * pbSubject, unsigned int * puiSubjectLen
		);

	/*
	功能名称:	获取证书公钥
	函数名称:	OpenSSL_CertGetPubkey
	输入参数:	pbX509Cert		证书内容
				uiX509CertLen		证书长度
	输出参数:	pbPublicKey	公钥内容
				puiPublicKeyLen		公钥长度
	返回值:   
	失败：
	功能描述:	获取证书公钥
	*/
	COMMON_API unsigned int OpenSSL_CertGetPubkey(
		const unsigned char * pbX509Cert, unsigned int uiX509CertLen,
		unsigned char * pbPublicKey, unsigned int * puiPublicKeyLen);
		
	COMMON_API unsigned int OpenSSL_CsrGetPubkey(const unsigned char *pbCSR, unsigned int uiCSRLen,
	unsigned char * pbPublicKey, unsigned int * puiPublicKeyLen);


	/*
	获取证书序列号
	*/
	COMMON_API unsigned int OpenSSL_CertGetSN(
		const unsigned char * pbX509Cert, unsigned int uiX509CertLen,
		unsigned char * pbSN, unsigned int * puiSNLen);

	/*
	功能名称:	获取证书主题项
	函数名称:	OpenSSL_CertGetSubjectItem
	输入参数:	
				pbX509Cert				证书内容
				uiX509CertLen			证书长度
				uiIndex					项标示
	输出参数:   
				pbSubjectItem			项值
				puiSubjectItemLen		项长度
	返回值:   
	失败：
	功能描述:	获取证书主题项
	*/
	COMMON_API unsigned int OpenSSL_CertGetSubjectItem(
		const unsigned char * pbX509Cert, unsigned int uiX509CertLen,
		int uiIndex, 
		unsigned char * pbSubjectItem, unsigned int * puiSubjectItemLen
		);

	/*
	功能名称:	SM2解密
	*/
	COMMON_API unsigned int OpenSSL_SM2Decrypt(
		const unsigned char * pbPrivateKey, unsigned int uiPrivateKeyLen, 
		const unsigned char * pbIN, unsigned int uiINLen,
		unsigned char * pbOUT, unsigned int * puiOUTLen
		);
	/*
	功能名称:	SM2加密
	*/
	COMMON_API unsigned int OpenSSL_SM2Encrypt(
		const unsigned char * pbPublicKeyX, unsigned int uiPublicKeyXLen, 
		const unsigned char * pbPublicKeyY, unsigned int uiPublicKeyYLen,
		const unsigned char * pbIN, unsigned int uiINLen,
		unsigned char * pbOUT, unsigned int * puiOUTLen);

	/*
	功能名称:	验证SM2点
	*/
	COMMON_API unsigned int OpenSSL_SM2Point(
		const unsigned char * pbPublicKeyX, unsigned int uiPublicKeyXLen, 
		const unsigned char * pbPublicKeyY, unsigned int uiPublicKeyYLen
		);

	/*
	功能名称:	加密内容输出文件
	*/
	COMMON_API unsigned int OpenSSL_SM2Write(
		const unsigned char * pbIN, unsigned int uiINLen, 
		unsigned int uiType,
		char * szFileName,
		unsigned int fileEncode, char * szPassword
		);

	/*
	功能名称:	SM2解密
	*/
	COMMON_API unsigned int OpenSSL_SM2DecryptInner(
		const unsigned char *pbIN, unsigned int uiINLen, 
		const unsigned char *pbPrivateKey, unsigned int uiPrivateKeyLen, 
		unsigned char *pbOUT, unsigned int * puiOUTLen
		);

	/*
	功能名称:	SM2加密
	*/
	COMMON_API unsigned int OpenSSL_SM2EncryptInner(
		const unsigned char *pbIN, unsigned int uiINLen, 
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen, 
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen, 
		unsigned char *pbOUT, unsigned int * puiOUTLen
		);

	/*
	功能名称:	获取证书公钥算法
	*/
	COMMON_API unsigned int OpenSSL_CertGetPublicKeyAlgor(
		const unsigned char * pbX509Cert, unsigned int uiX509CertLen,
		unsigned char *pbPublicKeyAlgor, unsigned int *puiPublicKeyAlgorLen
		);

	/*
	功能名称:	比较证书的颁发者和使用者
	*/
	COMMON_API unsigned int OpenSSL_CertSubjectCompareIssuer(const unsigned char * pbX509Cert, unsigned int uiX509CertLen,
		unsigned int * bEqual
		);

	COMMON_API unsigned int OpenSSL_CertExtenItem(const unsigned char * pbX509Cert, unsigned int uiX509CertLen,int uiIndex, unsigned char * pbSubjectItem, unsigned int * puiSubjectItemLen);

	/////////////////////////////////////////
	/////////////////////////////////////////
	/////////////////////////////////////////
	/////////////////////////////////////////

#if defined(GM_ECC_512_SUPPORT)
	// GM_ECC_512 start
	/*
	功能名称:	生成公私钥对
	函数名称:	OpenSSL_GMECC512GenKeys
	输入参数:	 
	输出参数:	pbPublicKeyX		公钥X
				pbPublicKeyY		公钥Y
				pbPrivateKey		私钥
	返回值:   
	失败：
	功能描述:	生成公私钥对
	*/
	COMMON_API unsigned int OpenSSL_GMECC512GenKeys(unsigned char * pbPublicKeyX,  unsigned int * puiPublicKeyXLen, 
		unsigned char * pbPublicKeyY,  unsigned int * puiPublicKeyYLen,
		unsigned char * pbPrivateKey,  unsigned int * puiPrivateKeyLen);


	/*
	功能名称:	生成证书请求
	函数名称:	OpenSSL_GMECC512GenCSRWithPubkey
	输入参数:	pbPublicKeyX     公钥X值
				uiPublicKeyXLen		公钥X长度
				pbPublicKeyY     公钥Y值
				uiPublicKeyYLen		公钥Y长度
	输出参数:	pbCSR		证书请求内容
				puiCSRLen		证书请求长度
	返回值:   
	失败：
	功能描述:	生成证书请求
	*/
	COMMON_API unsigned int OpenSSL_GMECC512GenCSRWithPubkey(const OPST_USERINFO *pstUserInfo,
		const unsigned char * pbPublicKeyX,  unsigned int uiPublicKeyXLen, 
		const unsigned char * pbPublicKeyY,  unsigned int uiPublicKeyYLen,
		unsigned char * pbCSR,  unsigned int * puiCSRLen);

	/*
	功能名称:	生成根证书
	函数名称:	OpenSSL_GMECC512GenRootCert
	输入参数:	pbCSR		请求信息
				uiCSRLen			请求长度
				uiSerialNumber	序列号
				uiNotBefore		开始时间
				uiNotAfter		结束时间
	输出参数:	pbX509Cert		证书内容
				puiX509CertLen		证书长度
	返回值:   
	失败：
	功能描述:	生成根证书
	*/
	COMMON_API unsigned int OpenSSL_GMECC512GenRootCert(const unsigned char * pbCSR,unsigned int uiCSRLen, 
		unsigned char * pbSerialNumber,unsigned int uiSerialNumberLen,
		unsigned int uiNotBefore, unsigned int uiNotAfter, 
		unsigned char * pbX509Cert, unsigned int * puiX509CertLen);

	/*
	功能名称:	生成GMECC512证书
	函数名称:	OpenSSL_GMECC512GenCert
	输入参数:	pbCSR		请求内容
				uiCSRLen			请求长度
				uiSerialNumber	序列号
				uiNotBefore		开始时间
				uiNotAfter		结束时间
	输出参数:	pbX509Cert		证书内容
				puiX509CertLen		证书长度
	返回值:   
	失败：
	功能描述:	生成GMECC512证书
	*/
	COMMON_API unsigned int OpenSSL_GMECC512GenCert(const unsigned char * pbCSR,unsigned int uiCSRLen, 
		const unsigned char * pbX509CACert, unsigned int uiX509CACertLen, 
		unsigned char * pbSerialNumber,unsigned int uiSerialNumberLen,
		unsigned int uiNotBefore, unsigned int uiNotAfter, unsigned int uiSignFlag,
		unsigned char * pbX509Cert, unsigned int * puiX509CertLen);
	
	/*
	功能名称:	生成GMECC512证书(扩展，验证并替换证书请求的公钥之后生成证书)
	函数名称:	OpenSSL_GMECC512GenCert
	输入参数:	pbCSR		请求内容
				uiCSRLen			请求长度
				uiSerialNumber	序列号
				uiNotBefore		开始时间
				uiNotAfter		结束时间
	输出参数:	pbX509Cert		证书内容
				puiX509CertLen		证书长度
	返回值:   
	失败：
	功能描述:	生成GMECC512证书
	*/
	COMMON_API unsigned int OpenSSL_GMECC512GenCertEX(const unsigned char * pbCSR,unsigned int uiCSRLen, 
		const unsigned char * pbPublicKeyX, unsigned int uiPublicKeyXLen, 
		const unsigned char * pbPublicKeyY, unsigned int uiPublicKeyYLen,
		const unsigned char * pbX509CACert, unsigned int uiX509CACertLen, 
		unsigned char * pbSerialNumber,unsigned int uiSerialNumberLen,
		unsigned int uiNotBefore, unsigned int uiNotAfter, unsigned int uiSignFlag,
		unsigned char * pbX509Cert, unsigned int * puiX509CertLen);

	/*
	功能名称:	证书吊销列表
	函数名称:	OpenSSL_GMECC512GenCRL
	输入参数:	pstCRLList				证书吊销内容
				uiCRLListSize			证书个数
				pbX509Cert			证书内容
				uiX509CertLen				证书长度
	输出参数:   
				pbCRL				证书吊销列表内容
				puiCRLLen				证书吊销列表长度
	返回值:   
	失败：
	功能描述:	证书吊销列表
	*/
	COMMON_API unsigned int OpenSSL_GMECC512GenCRL(const OPST_CRL * pstCRLList, unsigned int uiCRLListSize, 
		const unsigned char * pbX509Cert,unsigned int uiX509CertLen, 
		unsigned char * pbCRL, unsigned int * puiCRLLen);

	
	/*
	功能名称:	对证书进行签名
	函数名称:	OpenSSL_GMECC512SignCertWithKeys
	输入参数:	pbX509Cert					待签名证书内容
				uiX509CertLen				待签名证书长度
				pbPublicKeyX				签名者公钥X
				pbPublicKeyY				签名者公钥Y
				pbPrivateKey				私钥内容
				uiPrivateKeyLen				私钥长度
	输出参数:   pbX509CertSigned				签名证书内容
				puiX509CertSignedLen			签名证书长度
	返回值:   
	失败：
	功能描述:	对证书进行签名
	*/
	COMMON_API unsigned int OpenSSL_GMECC512SignCert(
		const unsigned char *pbX509Cert,  unsigned int uiX509CertLen, 
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen,
		const unsigned char *pbPrivateKey,  unsigned int uiPrivateKeyLen,
		unsigned char * pbX509CertSigned,  unsigned int * puiX509CertSignedLen
		);

	/*
	功能名称:	对证书请求进行签名
	函数名称:	OpenSSL_GMECC512SignCSR
	输入参数:	pbCSR					待签名证书请求内容
				uiCSRLen					待签名证书请求长度
				pbPrivateKey				私钥内容
				uiPrivateKeyLen				私钥长度
	输出参数:   pbCSRSigned				签名证书请求内容
				puiCSRSignedLen			签名证书请求长度
	返回值:   
	失败：
	功能描述:	对证书请求进行签名
	*/
	COMMON_API unsigned int OpenSSL_GMECC512SignCSR(
		const unsigned char *pbCSR, unsigned int uiCSRLen,
		const unsigned char * pbPrivateKey,unsigned int uiPrivateKeyLen,
		unsigned int uiAlg,
		unsigned char *pbCSRSigned, unsigned int * puiCSRSignedLen);

	/*
	功能名称:	对CRL进行签名
	函数名称:	OpenSSL_GMECC512SignCRL
	输入参数:	pbCRL					待签名CRL内容
				uiCRLLen					待签名CRL长度
				pbPublicKeyX				签名者公钥X
				pbPublicKeyY				签名者公钥Y
				pbPrivateKey				私钥内容
				uiPrivateKeyLen				私钥长度
	输出参数:   pbCRLSigned				签名CRL内容
				puiCRLSignedLen			签名CRL长度
	返回值:   
	失败：
	功能描述:	对CRL进行签名
	*/
	COMMON_API unsigned int OpenSSL_GMECC512SignCRL(
		const unsigned char *pbCRL, unsigned int uiCRLLen,unsigned int uiAlg,
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen,
		const unsigned char * pbPrivateKey,unsigned int uiPrivateKeyLen,
		unsigned char *pbCRLSigned, unsigned int * puiCRLSignedLen
		);

	/*
	功能名称:	对消息进行签名
	函数名称:	OpenSSL_GMECC512SignMSG
	输入参数:	pbMSG						待签名内容
				uiMSGLen					待签名长度
				pbPublicKeyX				签名者公钥X
				pbPublicKeyY				签名者公钥Y
				pbPrivateKey				私钥内容
				uiPrivateKeyLen				私钥长度
	输出参数:   pbCRLSigned				签名CRL内容
				puiCRLSignedLen			签名CRL长度
	返回值:   
	失败：
	功能描述:	对消息进行签名
	*/
	COMMON_API unsigned int OpenSSL_GMECC512SignMSG(const unsigned char *pbMSG, unsigned int uiMSGLen, 
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen,
		const unsigned char * pbPrivateKey,unsigned int uiPrivateKeyLen,
		unsigned int uiAlg,
		unsigned char *pbSig, unsigned int * puiSigLen);
	/*
	功能名称:	对HASH进行签名
	函数名称:	OpenSSL_GMECC512SignMSG
	输入参数:	pbHash						待签名hash内容
				uiHashLen					待签名hash长度
				pbPublicKeyX				签名者公钥X
				pbPublicKeyY				签名者公钥Y
				pbPrivateKey				私钥内容
				uiPrivateKeyLen				私钥长度
	输出参数:   pbCRLSigned				签名CRL内容
				puiCRLSignedLen			签名CRL长度
	返回值:   
	失败：
	功能描述:	对HASH进行签名
	*/
	COMMON_API unsigned int OpenSSL_GMECC512SignDigest(const unsigned char *pbHash, unsigned int uiHashLen, 
		const unsigned char *pbPrivateKey, unsigned int uiPrivateKeyLen,
		unsigned char *pbSig, unsigned int * puiSigLen
		);

	/*
	功能名称:	设置X509内容的签名值
	函数名称:	OpenSSL_GMECC512SetX509SignValue
	输入参数:	
	输出参数:   
	返回值:   
	失败：
	功能描述:	设置X509内容的签名值
	*/
	COMMON_API unsigned int OpenSSL_GMECC512SetX509SignValue(
		const unsigned char *pbX509, unsigned int uiX509Len,
		X509_TYPE uiX509Type,
		const unsigned char *pbR, unsigned int uiRLen,
		const unsigned char *pbS, unsigned int uiSLen,
		unsigned char *pbX509Signed, unsigned int * puiX509SignedLen);
	
	/*
	功能名称:	获取X509内容（不包含签名值）
	函数名称:	OpenSSL_GMECC512SetX509SignValue
	输入参数:	
	输出参数:   
	返回值:   
	失败：
	功能描述:	获取X509内容（不包含签名值）
	*/
	COMMON_API unsigned int OpenSSL_GetX509Content(
		const unsigned char *pbX509, unsigned int uiX509Len,
		X509_TYPE uiX509Type,
		unsigned char *pbX509Content, unsigned int *puiX509ContentLen
		);

	/*
	功能名称:	验证GMECC512签名
	函数名称:	OpenSSL_GMECC512VerifyDigest
	输入参数:	pbHash		HASH内容
				uiHashLen			HASH长度
				pbSig			签名内容
				uiSigLen				签名长度
				pbPublicKeyX		公钥X内容
				uiPublicKeyXLen			公钥X长度
				pbPublicKeyY		公钥Y内容
				uiPublicKeyYLen			公钥Y长度
	输出参数:
	返回值:   
	失败：
	功能描述:	验证GMECC512签名
	*/
	COMMON_API unsigned int OpenSSL_GMECC512VerifyDigest(const unsigned char *pbHash, unsigned int uiHashLen, 
		const unsigned char *pbSig, unsigned int uiSigLen,
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen);

	/*
	功能名称:	验证签名
	函数名称:	OpenSSL_GMECC512VerifyMSG
	输入参数:	pbMSG				原文内容
				uiMSGLen					原文长度
				pbSig				签名值内容
				uiSigLen					签名值长度
				pbPublicKeyX			公钥X内容
				uiPublicKeyXLen				公钥X长度
				pbPublicKeyY			公钥Y内容
				uiPublicKeyYLen				公钥Y长度
	输出参数:   
	返回值:   
	失败：
	功能描述:	验证签名
	*/
	COMMON_API unsigned int OpenSSL_GMECC512VerifyMSG(const unsigned char *pbMSG, unsigned int uiMSGLen, 
		const unsigned char *pbSig, unsigned int uiSigLen,
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen);

	/*
	功能名称:	验证请求
	函数名称:	OpenSSL_GMECC512VerifyCSR
	输入参数:	pbIN				请求内容
				uiINLen					请求长度
				pbSig				签名值内容
				uiSigLen					签名值长度
	输出参数:   
	返回值:   
	失败：
	功能描述:	验证请求
	*/
	COMMON_API unsigned int OpenSSL_GMECC512VerifyCSR(
		const unsigned char *pbCSR, unsigned int uiCSRLen,
		unsigned int uiAlg
		);

	/*
	功能名称:	验证证书
	函数名称:	OpenSSL_GMECC512VerifyCert
	输入参数:	pbX509Cert			证书内容
				uiX509CertLen				证书长度
				pbPublicKeyX			公钥X内容
				uiPublicKeyXLen				公钥X长度
				pbPublicKeyY			公钥Y内容
				uiPublicKeyYLen				公钥Y长度
	输出参数:   
	返回值:   
	失败：
	功能描述:	验证证书
	*/
	COMMON_API unsigned int OpenSSL_GMECC512VerifyCert(
		const unsigned char *pbX509Cert, unsigned int uiX509CertLen,unsigned int uiAlg,
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen
		);

	/*
	功能名称:	验证CRL
	函数名称:	OpenSSL_GMECC512VerifyCRL
	输入参数:	pbCRL					CRL内容
				uiCRLLen				CRL长度
				pbPublicKeyX			公钥X内容
				uiPublicKeyXLen			公钥X长度
				pbPublicKeyY			公钥Y内容
				uiPublicKeyYLen			公钥Y长度
	输出参数:   
	返回值:   
	失败：
	功能描述:	验证证书
	*/
	COMMON_API unsigned int OpenSSL_GMECC512VerifyCRL(
		const unsigned char *pbCRL, unsigned int uiCRLLen,unsigned int uiAlg,
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen
		);

	/*
	功能名称:	GMECC512解密
	*/
	COMMON_API unsigned int OpenSSL_GMECC512Decrypt(
		const unsigned char * pbPrivateKey, unsigned int uiPrivateKeyLen, 
		const unsigned char * pbIN, unsigned int uiINLen,
		unsigned char * pbOUT, unsigned int * puiOUTLen
		);
	/*
	功能名称:	GMECC512加密
	*/
	COMMON_API unsigned int OpenSSL_GMECC512Encrypt(
		const unsigned char * pbPublicKeyX, unsigned int uiPublicKeyXLen, 
		const unsigned char * pbPublicKeyY, unsigned int uiPublicKeyYLen,
		const unsigned char * pbIN, unsigned int uiINLen,
		unsigned char * pbOUT, unsigned int * puiOUTLen);

	/*
	功能名称:	验证GMECC512点
	*/
	COMMON_API unsigned int OpenSSL_GMECC512Point(
		const unsigned char * pbPublicKeyX, unsigned int uiPublicKeyXLen, 
		const unsigned char * pbPublicKeyY, unsigned int uiPublicKeyYLen
		);


	/*
	功能名称:	GMECC512解密
	*/
	COMMON_API unsigned int OpenSSL_GMECC512DecryptInner(
		const unsigned char *pbIN, unsigned int uiINLen, 
		const unsigned char *pbPrivateKey, unsigned int uiPrivateKeyLen, 
		unsigned char *pbOUT, unsigned int * puiOUTLen
		);

	/*
	功能名称:	GMECC512加密
	*/
	COMMON_API unsigned int OpenSSL_GMECC512EncryptInner(
		const unsigned char *pbIN, unsigned int uiINLen, 
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen, 
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen, 
		unsigned char *pbOUT, unsigned int * puiOUTLen
		);

	COMMON_API unsigned int OpenSSL_GMECC512GenPFX(const char *password,const char *nickname, 
		const unsigned char *pbPrivateKey, unsigned int uiPrivateKeyLen, 
		const unsigned char * pbPublicKeyX, unsigned int uiPublicKeyXLen, 
		const unsigned char * pbPublicKeyY, unsigned int uiPublicKeyYLen,
		const unsigned char * pbX509Cert, unsigned int uiX509CertLen,
		const unsigned char * pbX509CA, unsigned int uiX509CALen,
		int nid_key, int nid_cert, int iter, int mac_iter, int keytype,
		unsigned char *pbPFX, unsigned int * puiPFXLen
		);

	COMMON_API unsigned int OpenSSL_GMECC512GenExportEnvelopedKey(
		const unsigned char * pbPublicKeyX, unsigned int uiPublicKeyXLen, 
		const unsigned char * pbPublicKeyY, unsigned int uiPublicKeyYLen,
		unsigned char *pbOUT, unsigned int * puiOUTLen
		);

	COMMON_API unsigned int OpenSSL_GMECC512RestoreExportEnvelopedKey(
		const unsigned char * pbPublicKeyX, unsigned int uiPublicKeyXLen, 
		const unsigned char * pbPublicKeyY, unsigned int uiPublicKeyYLen,
		const unsigned char * pbOldPrivateKey, unsigned int uiOldPrivateKeyLen, 
		unsigned char *pbIN, unsigned int uiINLen,
		unsigned char *pbOUT, unsigned int * puiOUTLen
		);

	// GM_ECC_512 end 
#endif

#if defined(GM_ECC_512_SUPPORT_SKF)

	COMMON_API unsigned int SKF_GMECC512SignCert(
		const unsigned char *pbX509Cert,  unsigned int uiX509CertLen, 
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen,
		const char * pbPIN,unsigned int ulKeyTarget, unsigned int *pulRetry,
		unsigned char * pbX509CertSigned,  unsigned int * puiX509CertSignedLen
		);

	COMMON_API unsigned int SKF_GMECC512SignCRL(
		const unsigned char *pbCRL, unsigned int uiCRLLen,unsigned int uiAlg,
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen,
		const char * pbPIN,unsigned int ulKeyTarget, unsigned int *pulRetry,
		unsigned char *pbCRLSigned, unsigned int * puiCRLSignedLen
		);
#endif



	COMMON_API unsigned int OpenSSL_SM2GenPFX(const char *password,const char *nickname, 
		const unsigned char *pbPrivateKey, unsigned int uiPrivateKeyLen, 
		const unsigned char * pbPublicKeyX, unsigned int uiPublicKeyXLen, 
		const unsigned char * pbPublicKeyY, unsigned int uiPublicKeyYLen,
		const unsigned char * pbX509Cert, unsigned int uiX509CertLen,
		const unsigned char * pbX509CA, unsigned int uiX509CALen,
		int nid_key, int nid_cert, int iter, int mac_iter, int keytype,
		unsigned char *pbPFX, unsigned int * puiPFXLen
		);

	COMMON_API unsigned int OpenSSL_SM2GenExportEnvelopedKey(
		const unsigned char * pbPublicKeyX, unsigned int uiPublicKeyXLen, 
		const unsigned char * pbPublicKeyY, unsigned int uiPublicKeyYLen,
		unsigned char *pbOUT, unsigned int * puiOUTLen
		);

	COMMON_API unsigned int OpenSSL_SM2RestoreExportEnvelopedKey(
		const unsigned char * pbPublicKeyX, unsigned int uiPublicKeyXLen, 
		const unsigned char * pbPublicKeyY, unsigned int uiPublicKeyYLen,
		const unsigned char * pbOldPrivateKey, unsigned int uiOldPrivateKeyLen, 
		unsigned char *pbIN, unsigned int uiINLen,
		unsigned char *pbOUT, unsigned int * puiOUTLen
		);

	typedef struct _OPST_CERT_LIST{
		unsigned char * content;
		int contentLen;
	}OPST_CERT_LIST;

	COMMON_API unsigned int OpenSSL_P7BMake(
		OPST_CERT_LIST pX509List[],
		int uiX509ListLen,
		const unsigned char *pbCRL, unsigned int uiCRLLen,
		unsigned char *pbP7BContent, unsigned int *puiP7BContentLen
		);

#ifdef __cplusplus
}
#endif


#endif /*_OPENSSL_FUNC_DEF_H_*/