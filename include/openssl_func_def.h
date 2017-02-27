
#ifndef _OPENSSL_FUNC_DEF_H_
#define _OPENSSL_FUNC_DEF_H_

#include "o_all_type_def.h"

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif
	/*
	��������:	��ʼ����Դ
	��������:	OpenSSL_Initialize
	�������:	
	�������:	
	����ֵ:   
	ʧ�ܣ�
	��������:	��ʼ��OPENSSL
	*/
	COMMON_API unsigned int OpenSSL_Initialize();

	/*
	��������:	�ͷ���Դ
	��������:	OpenSSL_Finalize
	�������:	
	�������:	
	����ֵ:   
	ʧ�ܣ�
	��������:	�ͷ���Դ
	*/
	COMMON_API unsigned int OpenSSL_Finalize();

	/*
	��������:	���ɹ�˽Կ��
	��������:	OpenSSL_SM2GenKeys
	�������:	 
	�������:	pbPublicKeyX		��ԿX
				pbPublicKeyY		��ԿY
				pbPrivateKey		˽Կ
	����ֵ:   
	ʧ�ܣ�
	��������:	���ɹ�˽Կ��
	*/
	COMMON_API unsigned int OpenSSL_SM2GenKeys(unsigned char * pbPublicKeyX,  unsigned int * puiPublicKeyXLen, 
		unsigned char * pbPublicKeyY,  unsigned int * puiPublicKeyYLen,
		unsigned char * pbPrivateKey,  unsigned int * puiPrivateKeyLen);


	/*
	��������:	����֤������
	��������:	OpenSSL_SM2GenCSRWithPubkey
	�������:	pbPublicKeyX     ��ԿXֵ
				uiPublicKeyXLen		��ԿX����
				pbPublicKeyY     ��ԿYֵ
				uiPublicKeyYLen		��ԿY����
	�������:	pbCSR		֤����������
				puiCSRLen		֤�����󳤶�
	����ֵ:   
	ʧ�ܣ�
	��������:	����֤������
	*/
	COMMON_API unsigned int OpenSSL_SM2GenCSRWithPubkey(const OPST_USERINFO *pstUserInfo,
		const unsigned char * pbPublicKeyX,  unsigned int uiPublicKeyXLen, 
		const unsigned char * pbPublicKeyY,  unsigned int uiPublicKeyYLen,
		unsigned char * pbCSR,  unsigned int * puiCSRLen);

	/*
	��������:	���ɸ�֤��
	��������:	OpenSSL_SM2GenRootCert
	�������:	pbCSR		������Ϣ
				uiCSRLen			���󳤶�
				uiSerialNumber	���к�
				uiNotBefore		��ʼʱ��
				uiNotAfter		����ʱ��
	�������:	pbX509Cert		֤������
				puiX509CertLen		֤�鳤��
	����ֵ:   
	ʧ�ܣ�
	��������:	���ɸ�֤��
	*/
	COMMON_API unsigned int OpenSSL_SM2GenRootCert(const unsigned char * pbCSR,unsigned int uiCSRLen, 
		unsigned char * pbSerialNumber,unsigned int uiSerialNumberLen,
		unsigned int uiNotBefore, unsigned int uiNotAfter, 
		unsigned char * pbX509Cert, unsigned int * puiX509CertLen);

	/*
	��������:	����SM2֤��
	��������:	OpenSSL_SM2GenCert
	�������:	pbCSR		��������
				uiCSRLen			���󳤶�
				uiSerialNumber	���к�
				uiNotBefore		��ʼʱ��
				uiNotAfter		����ʱ��
	�������:	pbX509Cert		֤������
				puiX509CertLen		֤�鳤��
	����ֵ:   
	ʧ�ܣ�
	��������:	����SM2֤��
	*/
	COMMON_API unsigned int OpenSSL_SM2GenCert(const unsigned char * pbCSR,unsigned int uiCSRLen, 
		const unsigned char * pbX509CACert, unsigned int uiX509CACertLen, 
		unsigned char * pbSerialNumber,unsigned int uiSerialNumberLen,
		unsigned int uiNotBefore, unsigned int uiNotAfter, unsigned int uiSignFlag,
		unsigned char * pbX509Cert, unsigned int * puiX509CertLen);
	
	/*
	��������:	����SM2֤��(��չ����֤���滻֤������Ĺ�Կ֮������֤��)
	��������:	OpenSSL_SM2GenCert
	�������:	pbCSR		��������
				uiCSRLen			���󳤶�
				uiSerialNumber	���к�
				uiNotBefore		��ʼʱ��
				uiNotAfter		����ʱ��
	�������:	pbX509Cert		֤������
				puiX509CertLen		֤�鳤��
	����ֵ:   
	ʧ�ܣ�
	��������:	����SM2֤��
	*/
	COMMON_API unsigned int OpenSSL_SM2GenCertEX(const unsigned char * pbCSR,unsigned int uiCSRLen, 
		const unsigned char * pbPublicKeyX, unsigned int uiPublicKeyXLen, 
		const unsigned char * pbPublicKeyY, unsigned int uiPublicKeyYLen,
		const unsigned char * pbX509CACert, unsigned int uiX509CACertLen, 
		unsigned char * pbSerialNumber,unsigned int uiSerialNumberLen,
		unsigned int uiNotBefore, unsigned int uiNotAfter, unsigned int uiSignFlag,
		unsigned char * pbX509Cert, unsigned int * puiX509CertLen);

	/*
	��������:	֤������б�
	��������:	OpenSSL_SM2GenCRL
	�������:	pstCRLList				֤���������
				uiCRLListSize			֤�����
				pbX509Cert			֤������
				uiX509CertLen				֤�鳤��
	�������:   
				pbCRL				֤������б�����
				puiCRLLen				֤������б���
	����ֵ:   
	ʧ�ܣ�
	��������:	֤������б�
	*/
	COMMON_API unsigned int OpenSSL_SM2GenCRL(const OPST_CRL * pstCRLList, unsigned int uiCRLListSize, 
		const unsigned char * pbX509Cert,unsigned int uiX509CertLen, 
		unsigned char * pbCRL, unsigned int * puiCRLLen);

	
	/*
	��������:	��֤�����ǩ��
	��������:	OpenSSL_SM2SignCertWithKeys
	�������:	pbX509Cert					��ǩ��֤������
				uiX509CertLen				��ǩ��֤�鳤��
				pbPublicKeyX				ǩ���߹�ԿX
				pbPublicKeyY				ǩ���߹�ԿY
				pbPrivateKey				˽Կ����
				uiPrivateKeyLen				˽Կ����
	�������:   pbX509CertSigned				ǩ��֤������
				puiX509CertSignedLen			ǩ��֤�鳤��
	����ֵ:   
	ʧ�ܣ�
	��������:	��֤�����ǩ��
	*/
	COMMON_API unsigned int OpenSSL_SM2SignCert(
		const unsigned char *pbX509Cert,  unsigned int uiX509CertLen, 
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen,
		const unsigned char *pbPrivateKey,  unsigned int uiPrivateKeyLen,
		unsigned char * pbX509CertSigned,  unsigned int * puiX509CertSignedLen
		);

	/*
	��������:	��֤���������ǩ��
	��������:	OpenSSL_SM2SignCSR
	�������:	pbCSR					��ǩ��֤����������
				uiCSRLen					��ǩ��֤�����󳤶�
				pbPrivateKey				˽Կ����
				uiPrivateKeyLen				˽Կ����
	�������:   pbCSRSigned				ǩ��֤����������
				puiCSRSignedLen			ǩ��֤�����󳤶�
	����ֵ:   
	ʧ�ܣ�
	��������:	��֤���������ǩ��
	*/
	COMMON_API unsigned int OpenSSL_SM2SignCSR(
		const unsigned char *pbCSR, unsigned int uiCSRLen,
		const unsigned char * pbPrivateKey,unsigned int uiPrivateKeyLen,
		unsigned int uiAlg,
		unsigned char *pbCSRSigned, unsigned int * puiCSRSignedLen);

	/*
	��������:	��CRL����ǩ��
	��������:	OpenSSL_SM2SignCRL
	�������:	pbCRL					��ǩ��CRL����
				uiCRLLen					��ǩ��CRL����
				pbPublicKeyX				ǩ���߹�ԿX
				pbPublicKeyY				ǩ���߹�ԿY
				pbPrivateKey				˽Կ����
				uiPrivateKeyLen				˽Կ����
	�������:   pbCRLSigned				ǩ��CRL����
				puiCRLSignedLen			ǩ��CRL����
	����ֵ:   
	ʧ�ܣ�
	��������:	��CRL����ǩ��
	*/
	COMMON_API unsigned int OpenSSL_SM2SignCRL(
		const unsigned char *pbCRL, unsigned int uiCRLLen,unsigned int uiAlg,
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen,
		const unsigned char * pbPrivateKey,unsigned int uiPrivateKeyLen,
		unsigned char *pbCRLSigned, unsigned int * puiCRLSignedLen
		);

	/*
	��������:	����Ϣ����ǩ��
	��������:	OpenSSL_SM2SignMSG
	�������:	pbMSG						��ǩ������
				uiMSGLen					��ǩ������
				pbPublicKeyX				ǩ���߹�ԿX
				pbPublicKeyY				ǩ���߹�ԿY
				pbPrivateKey				˽Կ����
				uiPrivateKeyLen				˽Կ����
	�������:   pbCRLSigned				ǩ��CRL����
				puiCRLSignedLen			ǩ��CRL����
	����ֵ:   
	ʧ�ܣ�
	��������:	����Ϣ����ǩ��
	*/
	COMMON_API unsigned int OpenSSL_SM2SignMSG(const unsigned char *pbMSG, unsigned int uiMSGLen, 
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen,
		const unsigned char * pbPrivateKey,unsigned int uiPrivateKeyLen,
		unsigned int uiAlg,
		unsigned char *pbSig, unsigned int * puiSigLen);
	/*
	��������:	��HASH����ǩ��
	��������:	OpenSSL_SM2SignMSG
	�������:	pbHash						��ǩ��hash����
				uiHashLen					��ǩ��hash����
				pbPublicKeyX				ǩ���߹�ԿX
				pbPublicKeyY				ǩ���߹�ԿY
				pbPrivateKey				˽Կ����
				uiPrivateKeyLen				˽Կ����
	�������:   pbCRLSigned				ǩ��CRL����
				puiCRLSignedLen			ǩ��CRL����
	����ֵ:   
	ʧ�ܣ�
	��������:	��HASH����ǩ��
	*/
	COMMON_API unsigned int OpenSSL_SM2SignDigest(const unsigned char *pbHash, unsigned int uiHashLen, 
		const unsigned char *pbPrivateKey, unsigned int uiPrivateKeyLen,
		unsigned char *pbSig, unsigned int * puiSigLen
		);

	//X509�ṹ����
	typedef enum _X509_TYPE
	{
		X509_TYPE_CSR = 0,
		X509_TYPE_CERT = 1,
		X509_TYPE_CRL=2,
	}X509_TYPE;

	/*
	��������:	����X509���ݵ�ǩ��ֵ
	��������:	OpenSSL_SM2SetX509SignValue
	�������:	
	�������:   
	����ֵ:   
	ʧ�ܣ�
	��������:	����X509���ݵ�ǩ��ֵ
	*/
	COMMON_API unsigned int OpenSSL_SM2SetX509SignValue(
		const unsigned char *pbX509, unsigned int uiX509Len,
		X509_TYPE uiX509Type,
		const unsigned char *pbR, unsigned int uiRLen,
		const unsigned char *pbS, unsigned int uiSLen,
		unsigned char *pbX509Signed, unsigned int * puiX509SignedLen);
	
	/*
	��������:	��ȡX509���ݣ�������ǩ��ֵ��
	��������:	OpenSSL_SM2SetX509SignValue
	�������:	
	�������:   
	����ֵ:   
	ʧ�ܣ�
	��������:	��ȡX509���ݣ�������ǩ��ֵ��
	*/
	COMMON_API unsigned int OpenSSL_GetX509Content(
		const unsigned char *pbX509, unsigned int uiX509Len,
		X509_TYPE uiX509Type,
		unsigned char *pbX509Content, unsigned int *puiX509ContentLen
		);

	/*
	��������:	��֤SM2ǩ��
	��������:	OpenSSL_SM2VerifyDigest
	�������:	pbHash		HASH����
				uiHashLen			HASH����
				pbSig			ǩ������
				uiSigLen				ǩ������
				pbPublicKeyX		��ԿX����
				uiPublicKeyXLen			��ԿX����
				pbPublicKeyY		��ԿY����
				uiPublicKeyYLen			��ԿY����
	�������:
	����ֵ:   
	ʧ�ܣ�
	��������:	��֤SM2ǩ��
	*/
	COMMON_API unsigned int OpenSSL_SM2VerifyDigest(const unsigned char *pbHash, unsigned int uiHashLen, 
		const unsigned char *pbSig, unsigned int uiSigLen,
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen);

	/*
	��������:	��֤ǩ��
	��������:	OpenSSL_SM2VerifyMSG
	�������:	pbMSG				ԭ������
				uiMSGLen					ԭ�ĳ���
				pbSig				ǩ��ֵ����
				uiSigLen					ǩ��ֵ����
				pbPublicKeyX			��ԿX����
				uiPublicKeyXLen				��ԿX����
				pbPublicKeyY			��ԿY����
				uiPublicKeyYLen				��ԿY����
	�������:   
	����ֵ:   
	ʧ�ܣ�
	��������:	��֤ǩ��
	*/
	COMMON_API unsigned int OpenSSL_SM2VerifyMSG(const unsigned char *pbMSG, unsigned int uiMSGLen, 
		const unsigned char *pbSig, unsigned int uiSigLen,
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen);

	/*
	��������:	��֤����
	��������:	OpenSSL_SM2VerifyCSR
	�������:	pbIN				��������
				uiINLen					���󳤶�
				pbSig				ǩ��ֵ����
				uiSigLen					ǩ��ֵ����
	�������:   
	����ֵ:   
	ʧ�ܣ�
	��������:	��֤����
	*/
	COMMON_API unsigned int OpenSSL_SM2VerifyCSR(
		const unsigned char *pbCSR, unsigned int uiCSRLen,
		unsigned int uiAlg
		);

	/*
	��������:	��֤֤��
	��������:	OpenSSL_SM2VerifyCert
	�������:	pbX509Cert			֤������
				uiX509CertLen				֤�鳤��
				pbPublicKeyX			��ԿX����
				uiPublicKeyXLen				��ԿX����
				pbPublicKeyY			��ԿY����
				uiPublicKeyYLen				��ԿY����
	�������:   
	����ֵ:   
	ʧ�ܣ�
	��������:	��֤֤��
	*/
	COMMON_API unsigned int OpenSSL_SM2VerifyCert(
		const unsigned char *pbX509Cert, unsigned int uiX509CertLen,unsigned int uiAlg,
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen
		);

	/*
	��������:	��֤CRL
	��������:	OpenSSL_SM2VerifyCRL
	�������:	pbCRL					CRL����
				uiCRLLen				CRL����
				pbPublicKeyX			��ԿX����
				uiPublicKeyXLen			��ԿX����
				pbPublicKeyY			��ԿY����
				uiPublicKeyYLen			��ԿY����
	�������:   
	����ֵ:   
	ʧ�ܣ�
	��������:	��֤֤��
	*/
	COMMON_API unsigned int OpenSSL_SM2VerifyCRL(
		const unsigned char *pbCRL, unsigned int uiCRLLen,unsigned int uiAlg,
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen
		);

	/*
	��������:	��ȡ֤������
	��������:	OpenSSL_CertGetSubject
	�������:	pbX509Cert		֤������
				uiX509CertLen		֤�鳤��
	�������:	pbSubject	��������
				puiSubjectLen		���ⳤ��
	����ֵ:   
	ʧ�ܣ�
	��������:	��ȡ֤������
	*/
	COMMON_API unsigned int OpenSSL_CertGetSubject(
		const unsigned char * pbX509Cert, unsigned int uiX509CertLen,
		unsigned char * pbSubject, unsigned int * puiSubjectLen
		);

	/*
	��������:	��ȡ֤�鹫Կ
	��������:	OpenSSL_CertGetPubkey
	�������:	pbX509Cert		֤������
				uiX509CertLen		֤�鳤��
	�������:	pbPublicKey	��Կ����
				puiPublicKeyLen		��Կ����
	����ֵ:   
	ʧ�ܣ�
	��������:	��ȡ֤�鹫Կ
	*/
	COMMON_API unsigned int OpenSSL_CertGetPubkey(
		const unsigned char * pbX509Cert, unsigned int uiX509CertLen,
		unsigned char * pbPublicKey, unsigned int * puiPublicKeyLen);
		
	COMMON_API unsigned int OpenSSL_CsrGetPubkey(const unsigned char *pbCSR, unsigned int uiCSRLen,
	unsigned char * pbPublicKey, unsigned int * puiPublicKeyLen);


	/*
	��ȡ֤�����к�
	*/
	COMMON_API unsigned int OpenSSL_CertGetSN(
		const unsigned char * pbX509Cert, unsigned int uiX509CertLen,
		unsigned char * pbSN, unsigned int * puiSNLen);

	/*
	��������:	��ȡ֤��������
	��������:	OpenSSL_CertGetSubjectItem
	�������:	
				pbX509Cert				֤������
				uiX509CertLen			֤�鳤��
				uiIndex					���ʾ
	�������:   
				pbSubjectItem			��ֵ
				puiSubjectItemLen		���
	����ֵ:   
	ʧ�ܣ�
	��������:	��ȡ֤��������
	*/
	COMMON_API unsigned int OpenSSL_CertGetSubjectItem(
		const unsigned char * pbX509Cert, unsigned int uiX509CertLen,
		int uiIndex, 
		unsigned char * pbSubjectItem, unsigned int * puiSubjectItemLen
		);

	/*
	��������:	SM2����
	*/
	COMMON_API unsigned int OpenSSL_SM2Decrypt(
		const unsigned char * pbPrivateKey, unsigned int uiPrivateKeyLen, 
		const unsigned char * pbIN, unsigned int uiINLen,
		unsigned char * pbOUT, unsigned int * puiOUTLen
		);
	/*
	��������:	SM2����
	*/
	COMMON_API unsigned int OpenSSL_SM2Encrypt(
		const unsigned char * pbPublicKeyX, unsigned int uiPublicKeyXLen, 
		const unsigned char * pbPublicKeyY, unsigned int uiPublicKeyYLen,
		const unsigned char * pbIN, unsigned int uiINLen,
		unsigned char * pbOUT, unsigned int * puiOUTLen);

	/*
	��������:	��֤SM2��
	*/
	COMMON_API unsigned int OpenSSL_SM2Point(
		const unsigned char * pbPublicKeyX, unsigned int uiPublicKeyXLen, 
		const unsigned char * pbPublicKeyY, unsigned int uiPublicKeyYLen
		);

	/*
	��������:	������������ļ�
	*/
	COMMON_API unsigned int OpenSSL_SM2Write(
		const unsigned char * pbIN, unsigned int uiINLen, 
		unsigned int uiType,
		char * szFileName,
		unsigned int fileEncode, char * szPassword
		);

	/*
	��������:	SM2����
	*/
	COMMON_API unsigned int OpenSSL_SM2DecryptInner(
		const unsigned char *pbIN, unsigned int uiINLen, 
		const unsigned char *pbPrivateKey, unsigned int uiPrivateKeyLen, 
		unsigned char *pbOUT, unsigned int * puiOUTLen
		);

	/*
	��������:	SM2����
	*/
	COMMON_API unsigned int OpenSSL_SM2EncryptInner(
		const unsigned char *pbIN, unsigned int uiINLen, 
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen, 
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen, 
		unsigned char *pbOUT, unsigned int * puiOUTLen
		);

	/*
	��������:	��ȡ֤�鹫Կ�㷨
	*/
	COMMON_API unsigned int OpenSSL_CertGetPublicKeyAlgor(
		const unsigned char * pbX509Cert, unsigned int uiX509CertLen,
		unsigned char *pbPublicKeyAlgor, unsigned int *puiPublicKeyAlgorLen
		);

	/*
	��������:	�Ƚ�֤��İ䷢�ߺ�ʹ����
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
	��������:	���ɹ�˽Կ��
	��������:	OpenSSL_GMECC512GenKeys
	�������:	 
	�������:	pbPublicKeyX		��ԿX
				pbPublicKeyY		��ԿY
				pbPrivateKey		˽Կ
	����ֵ:   
	ʧ�ܣ�
	��������:	���ɹ�˽Կ��
	*/
	COMMON_API unsigned int OpenSSL_GMECC512GenKeys(unsigned char * pbPublicKeyX,  unsigned int * puiPublicKeyXLen, 
		unsigned char * pbPublicKeyY,  unsigned int * puiPublicKeyYLen,
		unsigned char * pbPrivateKey,  unsigned int * puiPrivateKeyLen);


	/*
	��������:	����֤������
	��������:	OpenSSL_GMECC512GenCSRWithPubkey
	�������:	pbPublicKeyX     ��ԿXֵ
				uiPublicKeyXLen		��ԿX����
				pbPublicKeyY     ��ԿYֵ
				uiPublicKeyYLen		��ԿY����
	�������:	pbCSR		֤����������
				puiCSRLen		֤�����󳤶�
	����ֵ:   
	ʧ�ܣ�
	��������:	����֤������
	*/
	COMMON_API unsigned int OpenSSL_GMECC512GenCSRWithPubkey(const OPST_USERINFO *pstUserInfo,
		const unsigned char * pbPublicKeyX,  unsigned int uiPublicKeyXLen, 
		const unsigned char * pbPublicKeyY,  unsigned int uiPublicKeyYLen,
		unsigned char * pbCSR,  unsigned int * puiCSRLen);

	/*
	��������:	���ɸ�֤��
	��������:	OpenSSL_GMECC512GenRootCert
	�������:	pbCSR		������Ϣ
				uiCSRLen			���󳤶�
				uiSerialNumber	���к�
				uiNotBefore		��ʼʱ��
				uiNotAfter		����ʱ��
	�������:	pbX509Cert		֤������
				puiX509CertLen		֤�鳤��
	����ֵ:   
	ʧ�ܣ�
	��������:	���ɸ�֤��
	*/
	COMMON_API unsigned int OpenSSL_GMECC512GenRootCert(const unsigned char * pbCSR,unsigned int uiCSRLen, 
		unsigned char * pbSerialNumber,unsigned int uiSerialNumberLen,
		unsigned int uiNotBefore, unsigned int uiNotAfter, 
		unsigned char * pbX509Cert, unsigned int * puiX509CertLen);

	/*
	��������:	����GMECC512֤��
	��������:	OpenSSL_GMECC512GenCert
	�������:	pbCSR		��������
				uiCSRLen			���󳤶�
				uiSerialNumber	���к�
				uiNotBefore		��ʼʱ��
				uiNotAfter		����ʱ��
	�������:	pbX509Cert		֤������
				puiX509CertLen		֤�鳤��
	����ֵ:   
	ʧ�ܣ�
	��������:	����GMECC512֤��
	*/
	COMMON_API unsigned int OpenSSL_GMECC512GenCert(const unsigned char * pbCSR,unsigned int uiCSRLen, 
		const unsigned char * pbX509CACert, unsigned int uiX509CACertLen, 
		unsigned char * pbSerialNumber,unsigned int uiSerialNumberLen,
		unsigned int uiNotBefore, unsigned int uiNotAfter, unsigned int uiSignFlag,
		unsigned char * pbX509Cert, unsigned int * puiX509CertLen);
	
	/*
	��������:	����GMECC512֤��(��չ����֤���滻֤������Ĺ�Կ֮������֤��)
	��������:	OpenSSL_GMECC512GenCert
	�������:	pbCSR		��������
				uiCSRLen			���󳤶�
				uiSerialNumber	���к�
				uiNotBefore		��ʼʱ��
				uiNotAfter		����ʱ��
	�������:	pbX509Cert		֤������
				puiX509CertLen		֤�鳤��
	����ֵ:   
	ʧ�ܣ�
	��������:	����GMECC512֤��
	*/
	COMMON_API unsigned int OpenSSL_GMECC512GenCertEX(const unsigned char * pbCSR,unsigned int uiCSRLen, 
		const unsigned char * pbPublicKeyX, unsigned int uiPublicKeyXLen, 
		const unsigned char * pbPublicKeyY, unsigned int uiPublicKeyYLen,
		const unsigned char * pbX509CACert, unsigned int uiX509CACertLen, 
		unsigned char * pbSerialNumber,unsigned int uiSerialNumberLen,
		unsigned int uiNotBefore, unsigned int uiNotAfter, unsigned int uiSignFlag,
		unsigned char * pbX509Cert, unsigned int * puiX509CertLen);

	/*
	��������:	֤������б�
	��������:	OpenSSL_GMECC512GenCRL
	�������:	pstCRLList				֤���������
				uiCRLListSize			֤�����
				pbX509Cert			֤������
				uiX509CertLen				֤�鳤��
	�������:   
				pbCRL				֤������б�����
				puiCRLLen				֤������б���
	����ֵ:   
	ʧ�ܣ�
	��������:	֤������б�
	*/
	COMMON_API unsigned int OpenSSL_GMECC512GenCRL(const OPST_CRL * pstCRLList, unsigned int uiCRLListSize, 
		const unsigned char * pbX509Cert,unsigned int uiX509CertLen, 
		unsigned char * pbCRL, unsigned int * puiCRLLen);

	
	/*
	��������:	��֤�����ǩ��
	��������:	OpenSSL_GMECC512SignCertWithKeys
	�������:	pbX509Cert					��ǩ��֤������
				uiX509CertLen				��ǩ��֤�鳤��
				pbPublicKeyX				ǩ���߹�ԿX
				pbPublicKeyY				ǩ���߹�ԿY
				pbPrivateKey				˽Կ����
				uiPrivateKeyLen				˽Կ����
	�������:   pbX509CertSigned				ǩ��֤������
				puiX509CertSignedLen			ǩ��֤�鳤��
	����ֵ:   
	ʧ�ܣ�
	��������:	��֤�����ǩ��
	*/
	COMMON_API unsigned int OpenSSL_GMECC512SignCert(
		const unsigned char *pbX509Cert,  unsigned int uiX509CertLen, 
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen,
		const unsigned char *pbPrivateKey,  unsigned int uiPrivateKeyLen,
		unsigned char * pbX509CertSigned,  unsigned int * puiX509CertSignedLen
		);

	/*
	��������:	��֤���������ǩ��
	��������:	OpenSSL_GMECC512SignCSR
	�������:	pbCSR					��ǩ��֤����������
				uiCSRLen					��ǩ��֤�����󳤶�
				pbPrivateKey				˽Կ����
				uiPrivateKeyLen				˽Կ����
	�������:   pbCSRSigned				ǩ��֤����������
				puiCSRSignedLen			ǩ��֤�����󳤶�
	����ֵ:   
	ʧ�ܣ�
	��������:	��֤���������ǩ��
	*/
	COMMON_API unsigned int OpenSSL_GMECC512SignCSR(
		const unsigned char *pbCSR, unsigned int uiCSRLen,
		const unsigned char * pbPrivateKey,unsigned int uiPrivateKeyLen,
		unsigned int uiAlg,
		unsigned char *pbCSRSigned, unsigned int * puiCSRSignedLen);

	/*
	��������:	��CRL����ǩ��
	��������:	OpenSSL_GMECC512SignCRL
	�������:	pbCRL					��ǩ��CRL����
				uiCRLLen					��ǩ��CRL����
				pbPublicKeyX				ǩ���߹�ԿX
				pbPublicKeyY				ǩ���߹�ԿY
				pbPrivateKey				˽Կ����
				uiPrivateKeyLen				˽Կ����
	�������:   pbCRLSigned				ǩ��CRL����
				puiCRLSignedLen			ǩ��CRL����
	����ֵ:   
	ʧ�ܣ�
	��������:	��CRL����ǩ��
	*/
	COMMON_API unsigned int OpenSSL_GMECC512SignCRL(
		const unsigned char *pbCRL, unsigned int uiCRLLen,unsigned int uiAlg,
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen,
		const unsigned char * pbPrivateKey,unsigned int uiPrivateKeyLen,
		unsigned char *pbCRLSigned, unsigned int * puiCRLSignedLen
		);

	/*
	��������:	����Ϣ����ǩ��
	��������:	OpenSSL_GMECC512SignMSG
	�������:	pbMSG						��ǩ������
				uiMSGLen					��ǩ������
				pbPublicKeyX				ǩ���߹�ԿX
				pbPublicKeyY				ǩ���߹�ԿY
				pbPrivateKey				˽Կ����
				uiPrivateKeyLen				˽Կ����
	�������:   pbCRLSigned				ǩ��CRL����
				puiCRLSignedLen			ǩ��CRL����
	����ֵ:   
	ʧ�ܣ�
	��������:	����Ϣ����ǩ��
	*/
	COMMON_API unsigned int OpenSSL_GMECC512SignMSG(const unsigned char *pbMSG, unsigned int uiMSGLen, 
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen,
		const unsigned char * pbPrivateKey,unsigned int uiPrivateKeyLen,
		unsigned int uiAlg,
		unsigned char *pbSig, unsigned int * puiSigLen);
	/*
	��������:	��HASH����ǩ��
	��������:	OpenSSL_GMECC512SignMSG
	�������:	pbHash						��ǩ��hash����
				uiHashLen					��ǩ��hash����
				pbPublicKeyX				ǩ���߹�ԿX
				pbPublicKeyY				ǩ���߹�ԿY
				pbPrivateKey				˽Կ����
				uiPrivateKeyLen				˽Կ����
	�������:   pbCRLSigned				ǩ��CRL����
				puiCRLSignedLen			ǩ��CRL����
	����ֵ:   
	ʧ�ܣ�
	��������:	��HASH����ǩ��
	*/
	COMMON_API unsigned int OpenSSL_GMECC512SignDigest(const unsigned char *pbHash, unsigned int uiHashLen, 
		const unsigned char *pbPrivateKey, unsigned int uiPrivateKeyLen,
		unsigned char *pbSig, unsigned int * puiSigLen
		);

	/*
	��������:	����X509���ݵ�ǩ��ֵ
	��������:	OpenSSL_GMECC512SetX509SignValue
	�������:	
	�������:   
	����ֵ:   
	ʧ�ܣ�
	��������:	����X509���ݵ�ǩ��ֵ
	*/
	COMMON_API unsigned int OpenSSL_GMECC512SetX509SignValue(
		const unsigned char *pbX509, unsigned int uiX509Len,
		X509_TYPE uiX509Type,
		const unsigned char *pbR, unsigned int uiRLen,
		const unsigned char *pbS, unsigned int uiSLen,
		unsigned char *pbX509Signed, unsigned int * puiX509SignedLen);
	
	/*
	��������:	��ȡX509���ݣ�������ǩ��ֵ��
	��������:	OpenSSL_GMECC512SetX509SignValue
	�������:	
	�������:   
	����ֵ:   
	ʧ�ܣ�
	��������:	��ȡX509���ݣ�������ǩ��ֵ��
	*/
	COMMON_API unsigned int OpenSSL_GetX509Content(
		const unsigned char *pbX509, unsigned int uiX509Len,
		X509_TYPE uiX509Type,
		unsigned char *pbX509Content, unsigned int *puiX509ContentLen
		);

	/*
	��������:	��֤GMECC512ǩ��
	��������:	OpenSSL_GMECC512VerifyDigest
	�������:	pbHash		HASH����
				uiHashLen			HASH����
				pbSig			ǩ������
				uiSigLen				ǩ������
				pbPublicKeyX		��ԿX����
				uiPublicKeyXLen			��ԿX����
				pbPublicKeyY		��ԿY����
				uiPublicKeyYLen			��ԿY����
	�������:
	����ֵ:   
	ʧ�ܣ�
	��������:	��֤GMECC512ǩ��
	*/
	COMMON_API unsigned int OpenSSL_GMECC512VerifyDigest(const unsigned char *pbHash, unsigned int uiHashLen, 
		const unsigned char *pbSig, unsigned int uiSigLen,
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen);

	/*
	��������:	��֤ǩ��
	��������:	OpenSSL_GMECC512VerifyMSG
	�������:	pbMSG				ԭ������
				uiMSGLen					ԭ�ĳ���
				pbSig				ǩ��ֵ����
				uiSigLen					ǩ��ֵ����
				pbPublicKeyX			��ԿX����
				uiPublicKeyXLen				��ԿX����
				pbPublicKeyY			��ԿY����
				uiPublicKeyYLen				��ԿY����
	�������:   
	����ֵ:   
	ʧ�ܣ�
	��������:	��֤ǩ��
	*/
	COMMON_API unsigned int OpenSSL_GMECC512VerifyMSG(const unsigned char *pbMSG, unsigned int uiMSGLen, 
		const unsigned char *pbSig, unsigned int uiSigLen,
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen);

	/*
	��������:	��֤����
	��������:	OpenSSL_GMECC512VerifyCSR
	�������:	pbIN				��������
				uiINLen					���󳤶�
				pbSig				ǩ��ֵ����
				uiSigLen					ǩ��ֵ����
	�������:   
	����ֵ:   
	ʧ�ܣ�
	��������:	��֤����
	*/
	COMMON_API unsigned int OpenSSL_GMECC512VerifyCSR(
		const unsigned char *pbCSR, unsigned int uiCSRLen,
		unsigned int uiAlg
		);

	/*
	��������:	��֤֤��
	��������:	OpenSSL_GMECC512VerifyCert
	�������:	pbX509Cert			֤������
				uiX509CertLen				֤�鳤��
				pbPublicKeyX			��ԿX����
				uiPublicKeyXLen				��ԿX����
				pbPublicKeyY			��ԿY����
				uiPublicKeyYLen				��ԿY����
	�������:   
	����ֵ:   
	ʧ�ܣ�
	��������:	��֤֤��
	*/
	COMMON_API unsigned int OpenSSL_GMECC512VerifyCert(
		const unsigned char *pbX509Cert, unsigned int uiX509CertLen,unsigned int uiAlg,
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen
		);

	/*
	��������:	��֤CRL
	��������:	OpenSSL_GMECC512VerifyCRL
	�������:	pbCRL					CRL����
				uiCRLLen				CRL����
				pbPublicKeyX			��ԿX����
				uiPublicKeyXLen			��ԿX����
				pbPublicKeyY			��ԿY����
				uiPublicKeyYLen			��ԿY����
	�������:   
	����ֵ:   
	ʧ�ܣ�
	��������:	��֤֤��
	*/
	COMMON_API unsigned int OpenSSL_GMECC512VerifyCRL(
		const unsigned char *pbCRL, unsigned int uiCRLLen,unsigned int uiAlg,
		const unsigned char *pbPublicKeyX, unsigned int uiPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int uiPublicKeyYLen
		);

	/*
	��������:	GMECC512����
	*/
	COMMON_API unsigned int OpenSSL_GMECC512Decrypt(
		const unsigned char * pbPrivateKey, unsigned int uiPrivateKeyLen, 
		const unsigned char * pbIN, unsigned int uiINLen,
		unsigned char * pbOUT, unsigned int * puiOUTLen
		);
	/*
	��������:	GMECC512����
	*/
	COMMON_API unsigned int OpenSSL_GMECC512Encrypt(
		const unsigned char * pbPublicKeyX, unsigned int uiPublicKeyXLen, 
		const unsigned char * pbPublicKeyY, unsigned int uiPublicKeyYLen,
		const unsigned char * pbIN, unsigned int uiINLen,
		unsigned char * pbOUT, unsigned int * puiOUTLen);

	/*
	��������:	��֤GMECC512��
	*/
	COMMON_API unsigned int OpenSSL_GMECC512Point(
		const unsigned char * pbPublicKeyX, unsigned int uiPublicKeyXLen, 
		const unsigned char * pbPublicKeyY, unsigned int uiPublicKeyYLen
		);


	/*
	��������:	GMECC512����
	*/
	COMMON_API unsigned int OpenSSL_GMECC512DecryptInner(
		const unsigned char *pbIN, unsigned int uiINLen, 
		const unsigned char *pbPrivateKey, unsigned int uiPrivateKeyLen, 
		unsigned char *pbOUT, unsigned int * puiOUTLen
		);

	/*
	��������:	GMECC512����
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