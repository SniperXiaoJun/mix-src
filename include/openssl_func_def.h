
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
				ulPublicKeyXLen		��ԿX����
				pbPublicKeyY     ��ԿYֵ
				ulPublicKeyYLen		��ԿY����
	�������:	pbCSR		֤����������
				pulCSRLen		֤�����󳤶�
	����ֵ:   
	ʧ�ܣ�
	��������:	����֤������
	*/
	COMMON_API unsigned int OpenSSL_SM2GenCSRWithPubkey(const OPST_USERINFO *pstUserInfo,
		const unsigned char * pbPublicKeyX,  unsigned int ulPublicKeyXLen, 
		const unsigned char * pbPublicKeyY,  unsigned int ulPublicKeyYLen,
		unsigned char * pbCSR,  unsigned int * puiCSRLen);

	/*
	��������:	���ɸ�֤��
	��������:	OpenSSL_SM2GenRootCert
	�������:	pbCSR		������Ϣ
				ulCSRLen			���󳤶�
				ulSerialNumber	���к�
				ulNotBefore		��ʼʱ��
				ulNotAfter		����ʱ��
	�������:	pbX509Cert		֤������
				pulX509CertLen		֤�鳤��
	����ֵ:   
	ʧ�ܣ�
	��������:	���ɸ�֤��
	*/
	COMMON_API unsigned int OpenSSL_SM2GenRootCert(const unsigned char * pbCSR,unsigned int ulCSRLen, 
		unsigned char * pbSerialNumber,unsigned int ulSerialNumberLen,
		unsigned int ulNotBefore, unsigned int ulNotAfter, 
		unsigned char * pbX509Cert, unsigned int * puiX509CertLen);

	/*
	��������:	����SM2֤��
	��������:	OpenSSL_SM2GenCert
	�������:	pbCSR		��������
				ulCSRLen			���󳤶�
				ulSerialNumber	���к�
				ulNotBefore		��ʼʱ��
				ulNotAfter		����ʱ��
	�������:	pbX509Cert		֤������
				pulX509CertLen		֤�鳤��
	����ֵ:   
	ʧ�ܣ�
	��������:	����SM2֤��
	*/
	COMMON_API unsigned int OpenSSL_SM2GenCert(const unsigned char * pbCSR,unsigned int ulCSRLen, 
		const unsigned char * pbX509CACert, unsigned int ulX509CACertLen, 
		unsigned char * pbSerialNumber,unsigned int ulSerialNumberLen,
		unsigned int ulNotBefore, unsigned int ulNotAfter, unsigned int ulSignFlag,
		unsigned char * pbX509Cert, unsigned int * puiX509CertLen);
	
	/*
	��������:	����SM2֤��(��չ����֤���滻֤������Ĺ�Կ֮������֤��)
	��������:	OpenSSL_SM2GenCert
	�������:	pbCSR		��������
				ulCSRLen			���󳤶�
				ulSerialNumber	���к�
				ulNotBefore		��ʼʱ��
				ulNotAfter		����ʱ��
	�������:	pbX509Cert		֤������
				pulX509CertLen		֤�鳤��
	����ֵ:   
	ʧ�ܣ�
	��������:	����SM2֤��
	*/
	COMMON_API unsigned int OpenSSL_SM2GenCertEX(const unsigned char * pbCSR,unsigned int ulCSRLen, 
		const unsigned char * pbPublicKeyX, unsigned int ulPublicKeyXLen, 
		const unsigned char * pbPublicKeyY, unsigned int ulPublicKeyYLen,
		const unsigned char * pbX509CACert, unsigned int ulX509CACertLen, 
		unsigned char * pbSerialNumber,unsigned int ulSerialNumberLen,
		unsigned int ulNotBefore, unsigned int ulNotAfter, unsigned int ulSignFlag,
		unsigned char * pbX509Cert, unsigned int * puiX509CertLen);

	/*
	��������:	֤������б�
	��������:	OpenSSL_SM2GenCRL
	�������:	pstCRLList				֤���������
				ulCRLListSize			֤�����
				pbX509Cert			֤������
				ulX509CertLen				֤�鳤��
	�������:   
				pbCRL				֤������б�����
				pulCRLLen				֤������б���
	����ֵ:   
	ʧ�ܣ�
	��������:	֤������б�
	*/
	COMMON_API unsigned int OpenSSL_SM2GenCRL(const OPST_CRL * pstCRLList, unsigned int ulCRLListSize, 
		const unsigned char * pbX509Cert,unsigned int ulX509CertLen, 
		unsigned char * pbCRL, unsigned int * puiCRLLen);

	
	/*
	��������:	��֤�����ǩ��
	��������:	OpenSSL_SM2SignCertWithKeys
	�������:	pbX509Cert					��ǩ��֤������
				ulX509CertLen				��ǩ��֤�鳤��
				pbPublicKeyX				ǩ���߹�ԿX
				pbPublicKeyY				ǩ���߹�ԿY
				pbPrivateKey				˽Կ����
				ulPrivateKeyLen				˽Կ����
	�������:   pbX509CertSigned				ǩ��֤������
				pulX509CertSignedLen			ǩ��֤�鳤��
	����ֵ:   
	ʧ�ܣ�
	��������:	��֤�����ǩ��
	*/
	COMMON_API unsigned int OpenSSL_SM2SignCert(
		const unsigned char *pbX509Cert,  unsigned int ulX509CertLen, 
		const unsigned char *pbPublicKeyX, unsigned int ulPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int ulPublicKeyYLen,
		const unsigned char *pbPrivateKey,  unsigned int ulPrivateKeyLen,
		unsigned char * pbX509CertSigned,  unsigned int * puiX509CertSignedLen
		);

	/*
	��������:	��֤���������ǩ��
	��������:	OpenSSL_SM2SignCSR
	�������:	pbCSR					��ǩ��֤����������
				ulCSRLen					��ǩ��֤�����󳤶�
				pbPrivateKey				˽Կ����
				ulPrivateKeyLen				˽Կ����
	�������:   pbCSRSigned				ǩ��֤����������
				pulCSRSignedLen			ǩ��֤�����󳤶�
	����ֵ:   
	ʧ�ܣ�
	��������:	��֤���������ǩ��
	*/
	COMMON_API unsigned int OpenSSL_SM2SignCSR(
		const unsigned char *pbCSR, unsigned int ulCSRLen,
		const unsigned char * pbPrivateKey,unsigned int ulPrivateKeyLen,
		unsigned int ulAlg,
		unsigned char *pbCSRSigned, unsigned int * puiCSRSignedLen);

	/*
	��������:	��CRL����ǩ��
	��������:	OpenSSL_SM2SignCRL
	�������:	pbCRL					��ǩ��CRL����
				ulCRLLen					��ǩ��CRL����
				pbPublicKeyX				ǩ���߹�ԿX
				pbPublicKeyY				ǩ���߹�ԿY
				pbPrivateKey				˽Կ����
				ulPrivateKeyLen				˽Կ����
	�������:   pbCRLSigned				ǩ��CRL����
				pulCRLSignedLen			ǩ��CRL����
	����ֵ:   
	ʧ�ܣ�
	��������:	��CRL����ǩ��
	*/
	COMMON_API unsigned int OpenSSL_SM2SignCRL(
		const unsigned char *pbCRL, unsigned int ulCRLLen,unsigned int ulAlg,
		const unsigned char *pbPublicKeyX, unsigned int ulPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int ulPublicKeyYLen,
		const unsigned char * pbPrivateKey,unsigned int ulPrivateKeyLen,
		unsigned char *pbCRLSigned, unsigned int * puiCRLSignedLen
		);

	/*
	��������:	����Ϣ����ǩ��
	��������:	OpenSSL_SM2SignMSG
	�������:	pbMSG						��ǩ������
				ulMSGLen					��ǩ������
				pbPublicKeyX				ǩ���߹�ԿX
				pbPublicKeyY				ǩ���߹�ԿY
				pbPrivateKey				˽Կ����
				ulPrivateKeyLen				˽Կ����
	�������:   pbCRLSigned				ǩ��CRL����
				pulCRLSignedLen			ǩ��CRL����
	����ֵ:   
	ʧ�ܣ�
	��������:	����Ϣ����ǩ��
	*/
	COMMON_API unsigned int OpenSSL_SM2SignMSG(const unsigned char *pbMSG, unsigned int ulMSGLen, 
		const unsigned char *pbPublicKeyX, unsigned int ulPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int ulPublicKeyYLen,
		const unsigned char * pbPrivateKey,unsigned int ulPrivateKeyLen,
		unsigned int ulAlg,
		unsigned char *pbSig, unsigned int * puiSigLen);
	/*
	��������:	��HASH����ǩ��
	��������:	OpenSSL_SM2SignMSG
	�������:	pbHash						��ǩ��hash����
				ulHashLen					��ǩ��hash����
				pbPublicKeyX				ǩ���߹�ԿX
				pbPublicKeyY				ǩ���߹�ԿY
				pbPrivateKey				˽Կ����
				ulPrivateKeyLen				˽Կ����
	�������:   pbCRLSigned				ǩ��CRL����
				pulCRLSignedLen			ǩ��CRL����
	����ֵ:   
	ʧ�ܣ�
	��������:	��HASH����ǩ��
	*/
	COMMON_API unsigned int OpenSSL_SM2SignDigest(const unsigned char *pbHash, unsigned int ulHashLen, 
		const unsigned char *pbPrivateKey, unsigned int ulPrivateKeyLen,
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
		const unsigned char *pbX509, unsigned int ulX509Len,
		X509_TYPE ulX509Type,
		const unsigned char *pbR, unsigned int ulRLen,
		const unsigned char *pbS, unsigned int ulSLen,
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
		const unsigned char *pbX509, unsigned int ulX509Len,
		X509_TYPE ulX509Type,
		unsigned char *pbX509Content, unsigned int *pulX509ContentLen
		);

	/*
	��������:	��֤SM2ǩ��
	��������:	OpenSSL_SM2VerifyDigest
	�������:	pbHash		HASH����
				ulHashLen			HASH����
				pbSig			ǩ������
				ulSigLen				ǩ������
				pbPublicKeyX		��ԿX����
				ulPublicKeyXLen			��ԿX����
				pbPublicKeyY		��ԿY����
				ulPublicKeyYLen			��ԿY����
	�������:
	����ֵ:   
	ʧ�ܣ�
	��������:	��֤SM2ǩ��
	*/
	COMMON_API unsigned int OpenSSL_SM2VerifyDigest(const unsigned char *pbHash, unsigned int ulHashLen, 
		const unsigned char *pbSig, unsigned int ulSigLen,
		const unsigned char *pbPublicKeyX, unsigned int ulPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int ulPublicKeyYLen);

	/*
	��������:	��֤ǩ��
	��������:	OpenSSL_SM2VerifyMSG
	�������:	pbMSG				ԭ������
				ulMSGLen					ԭ�ĳ���
				pbSig				ǩ��ֵ����
				ulSigLen					ǩ��ֵ����
				pbPublicKeyX			��ԿX����
				ulPublicKeyXLen				��ԿX����
				pbPublicKeyY			��ԿY����
				ulPublicKeyYLen				��ԿY����
	�������:   
	����ֵ:   
	ʧ�ܣ�
	��������:	��֤ǩ��
	*/
	COMMON_API unsigned int OpenSSL_SM2VerifyMSG(const unsigned char *pbMSG, unsigned int ulMSGLen, 
		const unsigned char *pbSig, unsigned int ulSigLen,
		const unsigned char *pbPublicKeyX, unsigned int ulPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int ulPublicKeyYLen);

	/*
	��������:	��֤����
	��������:	OpenSSL_SM2VerifyCSR
	�������:	pbIN				��������
				ulINLen					���󳤶�
				pbSig				ǩ��ֵ����
				ulSigLen					ǩ��ֵ����
	�������:   
	����ֵ:   
	ʧ�ܣ�
	��������:	��֤����
	*/
	COMMON_API unsigned int OpenSSL_SM2VerifyCSR(
		const unsigned char *pbCSR, unsigned int ulCSRLen,
		unsigned int ulAlg
		);

	/*
	��������:	��֤֤��
	��������:	OpenSSL_SM2VerifyCert
	�������:	pbX509Cert			֤������
				ulX509CertLen				֤�鳤��
				pbPublicKeyX			��ԿX����
				ulPublicKeyXLen				��ԿX����
				pbPublicKeyY			��ԿY����
				ulPublicKeyYLen				��ԿY����
	�������:   
	����ֵ:   
	ʧ�ܣ�
	��������:	��֤֤��
	*/
	COMMON_API unsigned int OpenSSL_SM2VerifyCert(
		const unsigned char *pbX509Cert, unsigned int ulX509CertLen,unsigned int ulAlg,
		const unsigned char *pbPublicKeyX, unsigned int ulPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int ulPublicKeyYLen
		);

	/*
	��������:	��֤CRL
	��������:	OpenSSL_SM2VerifyCRL
	�������:	pbCRL					CRL����
				ulCRLLen				CRL����
				pbPublicKeyX			��ԿX����
				ulPublicKeyXLen			��ԿX����
				pbPublicKeyY			��ԿY����
				ulPublicKeyYLen			��ԿY����
	�������:   
	����ֵ:   
	ʧ�ܣ�
	��������:	��֤֤��
	*/
	COMMON_API unsigned int OpenSSL_SM2VerifyCRL(
		const unsigned char *pbCRL, unsigned int ulCRLLen,unsigned int ulAlg,
		const unsigned char *pbPublicKeyX, unsigned int ulPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int ulPublicKeyYLen
		);

	/*
	��������:	��ȡ֤������
	��������:	OpenSSL_CertGetSubject
	�������:	pbX509Cert		֤������
				ulX509CertLen		֤�鳤��
	�������:	pbSubject	��������
				pulSubjectLen		���ⳤ��
	����ֵ:   
	ʧ�ܣ�
	��������:	��ȡ֤������
	*/
	COMMON_API unsigned int OpenSSL_CertGetSubject(
		const unsigned char * pbX509Cert, unsigned int ulX509CertLen,
		unsigned char * pbSubject, unsigned int * puiSubjectLen
		);

	/*
	��������:	��ȡ֤�鹫Կ
	��������:	OpenSSL_CertGetPubkey
	�������:	pbX509Cert		֤������
				ulX509CertLen		֤�鳤��
	�������:	pbPublicKey	��Կ����
				pulPublicKeyLen		��Կ����
	����ֵ:   
	ʧ�ܣ�
	��������:	��ȡ֤�鹫Կ
	*/
	COMMON_API unsigned int OpenSSL_CertGetPubkey(
		const unsigned char * pbX509Cert, unsigned int ulX509CertLen,
		unsigned char * pbPublicKey, unsigned int * puiPublicKeyLen);


	/*
	��ȡ֤�����к�
	*/
	COMMON_API unsigned int OpenSSL_CertGetSN(
		const unsigned char * pbX509Cert, unsigned int ulX509CertLen,
		unsigned char * pbSN, unsigned int * puiSNLen);

	/*
	��������:	��ȡ֤��������
	��������:	OpenSSL_CertGetSubjectItem
	�������:	
				pbX509Cert				֤������
				ulX509CertLen			֤�鳤��
				ulIndex					���ʾ
	�������:   
				pbSubjectItem			��ֵ
				pulSubjectItemLen		���
	����ֵ:   
	ʧ�ܣ�
	��������:	��ȡ֤��������
	*/
	COMMON_API unsigned int OpenSSL_CertGetSubjectItem(
		const unsigned char * pbX509Cert, unsigned int ulX509CertLen,
		int ulIndex, 
		unsigned char * pbSubjectItem, unsigned int * puiSubjectItemLen
		);

	/*
	��������:	SM2����
	*/
	COMMON_API unsigned int OpenSSL_SM2Decrypt(
		const unsigned char * pbPrivateKey, unsigned int ulPrivateKeyLen, 
		const unsigned char * pbIN, unsigned int ulINLen,
		unsigned char * pbOUT, unsigned int * puiOUTLen
		);
	/*
	��������:	SM2����
	*/
	COMMON_API unsigned int OpenSSL_SM2Encrypt(
		const unsigned char * pbPublicKeyX, unsigned int ulPublicKeyXLen, 
		const unsigned char * pbPublicKeyY, unsigned int ulPublicKeyYLen,
		const unsigned char * pbIN, unsigned int ulINLen,
		unsigned char * pbOUT, unsigned int * puiOUTLen);

	/*
	��������:	��֤SM2��
	*/
	COMMON_API unsigned int OpenSSL_SM2Point(
		const unsigned char * pbPublicKeyX, unsigned int ulPublicKeyXLen, 
		const unsigned char * pbPublicKeyY, unsigned int ulPublicKeyYLen
		);

	/*
	��������:	������������ļ�
	*/
	COMMON_API unsigned int OpenSSL_SM2Write(
		const unsigned char * pbIN, unsigned int ulINLen, 
		unsigned int ulType,
		char * szFileName,
		unsigned int fileEncode, char * szPassword
		);

	/*
	��������:	SM2����
	*/
	COMMON_API unsigned int OpenSSL_SM2DecryptInner(
		const unsigned char *pbIN, unsigned int ulINLen, 
		const unsigned char *pbPrivateKey, unsigned int ulPrivateKeyLen, 
		unsigned char *pbOUT, unsigned int * puiOUTLen
		);

	/*
	��������:	SM2����
	*/
	COMMON_API unsigned int OpenSSL_SM2EncryptInner(
		const unsigned char *pbIN, unsigned int ulINLen, 
		const unsigned char *pbPublicKeyX, unsigned int ulPublicKeyXLen, 
		const unsigned char *pbPublicKeyY, unsigned int ulPublicKeyYLen, 
		unsigned char *pbOUT, unsigned int * puiOUTLen
		);

	/*
	��������:	��ȡ֤�鹫Կ�㷨
	*/
	COMMON_API unsigned int OpenSSL_CertGetPublicKeyAlgor(
		const unsigned char * pbX509Cert, unsigned int ulX509CertLen,
		unsigned char *pbPublicKeyAlgor, unsigned int *pulPublicKeyAlgorLen
		);

	/*
	��������:	�Ƚ�֤��İ䷢�ߺ�ʹ����
	*/
	COMMON_API unsigned int OpenSSL_CertSubjectCompareIssuer(const unsigned char * pbX509Cert, unsigned int ulX509CertLen,
		unsigned int * bEqual
		);

	COMMON_API unsigned int OpenSSL_CertExtenItem(const unsigned char * pbX509Cert, unsigned int ulX509CertLen,int ulIndex, unsigned char * pbSubjectItem, unsigned int * puiSubjectItemLen);

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
				ulPublicKeyXLen		��ԿX����
				pbPublicKeyY     ��ԿYֵ
				ulPublicKeyYLen		��ԿY����
	�������:	pbCSR		֤����������
				pulCSRLen		֤�����󳤶�
	����ֵ:   
	ʧ�ܣ�
	��������:	����֤������
	*/
	COMMON_API unsigned int OpenSSL_GMECC512GenCSRWithPubkey(const OPST_USERINFO *pstUserInfo,
		const unsigned char * pbPublicKeyX,  unsigned int ulPublicKeyXLen, 
		const unsigned char * pbPublicKeyY,  unsigned int ulPublicKeyYLen,
		unsigned char * pbCSR,  unsigned int * puiCSRLen);

	/*
	��������:	���ɸ�֤��
	��������:	OpenSSL_GMECC512GenRootCert
	�������:	pbCSR		������Ϣ
				ulCSRLen			���󳤶�
				ulSerialNumber	���к�
				ulNotBefore		��ʼʱ��
				ulNotAfter		����ʱ��
	�������:	pbX509Cert		֤������
				pulX509CertLen		֤�鳤��
	����ֵ:   
	ʧ�ܣ�
	��������:	���ɸ�֤��
	*/
	COMMON_API unsigned int OpenSSL_GMECC512GenRootCert(const unsigned char * pbCSR,unsigned int ulCSRLen, 
		unsigned char * pbSerialNumber,unsigned int ulSerialNumberLen,
		unsigned int ulNotBefore, unsigned int ulNotAfter, 
		unsigned char * pbX509Cert, unsigned int * puiX509CertLen);

	/*
	��������:	����GMECC512֤��
	��������:	OpenSSL_GMECC512GenCert
	�������:	pbCSR		��������
				ulCSRLen			���󳤶�
				ulSerialNumber	���к�
				ulNotBefore		��ʼʱ��
				ulNotAfter		����ʱ��
	�������:	pbX509Cert		֤������
				pulX509CertLen		֤�鳤��
	����ֵ:   
	ʧ�ܣ�
	��������:	����GMECC512֤��
	*/
	COMMON_API unsigned int OpenSSL_GMECC512GenCert(const unsigned char * pbCSR,unsigned int ulCSRLen, 
		const unsigned char * pbX509CACert, unsigned int ulX509CACertLen, 
		unsigned char * pbSerialNumber,unsigned int ulSerialNumberLen,
		unsigned int ulNotBefore, unsigned int ulNotAfter, unsigned int ulSignFlag,
		unsigned char * pbX509Cert, unsigned int * puiX509CertLen);
	
	/*
	��������:	����GMECC512֤��(��չ����֤���滻֤������Ĺ�Կ֮������֤��)
	��������:	OpenSSL_GMECC512GenCert
	�������:	pbCSR		��������
				ulCSRLen			���󳤶�
				ulSerialNumber	���к�
				ulNotBefore		��ʼʱ��
				ulNotAfter		����ʱ��
	�������:	pbX509Cert		֤������
				pulX509CertLen		֤�鳤��
	����ֵ:   
	ʧ�ܣ�
	��������:	����GMECC512֤��
	*/
	COMMON_API unsigned int OpenSSL_GMECC512GenCertEX(const unsigned char * pbCSR,unsigned int ulCSRLen, 
		const unsigned char * pbPublicKeyX, unsigned int ulPublicKeyXLen, 
		const unsigned char * pbPublicKeyY, unsigned int ulPublicKeyYLen,
		const unsigned char * pbX509CACert, unsigned int ulX509CACertLen, 
		unsigned char * pbSerialNumber,unsigned int ulSerialNumberLen,
		unsigned int ulNotBefore, unsigned int ulNotAfter, unsigned int ulSignFlag,
		unsigned char * pbX509Cert, unsigned int * puiX509CertLen);

	/*
	��������:	֤������б�
	��������:	OpenSSL_GMECC512GenCRL
	�������:	pstCRLList				֤���������
				ulCRLListSize			֤�����
				pbX509Cert			֤������
				ulX509CertLen				֤�鳤��
	�������:   
				pbCRL				֤������б�����
				pulCRLLen				֤������б���
	����ֵ:   
	ʧ�ܣ�
	��������:	֤������б�
	*/
	COMMON_API unsigned int OpenSSL_GMECC512GenCRL(const OPST_CRL * pstCRLList, unsigned int ulCRLListSize, 
		const unsigned char * pbX509Cert,unsigned int ulX509CertLen, 
		unsigned char * pbCRL, unsigned int * puiCRLLen);

	
	/*
	��������:	��֤�����ǩ��
	��������:	OpenSSL_GMECC512SignCertWithKeys
	�������:	pbX509Cert					��ǩ��֤������
				ulX509CertLen				��ǩ��֤�鳤��
				pbPublicKeyX				ǩ���߹�ԿX
				pbPublicKeyY				ǩ���߹�ԿY
				pbPrivateKey				˽Կ����
				ulPrivateKeyLen				˽Կ����
	�������:   pbX509CertSigned				ǩ��֤������
				pulX509CertSignedLen			ǩ��֤�鳤��
	����ֵ:   
	ʧ�ܣ�
	��������:	��֤�����ǩ��
	*/
	COMMON_API unsigned int OpenSSL_GMECC512SignCert(
		const unsigned char *pbX509Cert,  unsigned int ulX509CertLen, 
		const unsigned char *pbPublicKeyX, unsigned int ulPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int ulPublicKeyYLen,
		const unsigned char *pbPrivateKey,  unsigned int ulPrivateKeyLen,
		unsigned char * pbX509CertSigned,  unsigned int * puiX509CertSignedLen
		);

	/*
	��������:	��֤���������ǩ��
	��������:	OpenSSL_GMECC512SignCSR
	�������:	pbCSR					��ǩ��֤����������
				ulCSRLen					��ǩ��֤�����󳤶�
				pbPrivateKey				˽Կ����
				ulPrivateKeyLen				˽Կ����
	�������:   pbCSRSigned				ǩ��֤����������
				pulCSRSignedLen			ǩ��֤�����󳤶�
	����ֵ:   
	ʧ�ܣ�
	��������:	��֤���������ǩ��
	*/
	COMMON_API unsigned int OpenSSL_GMECC512SignCSR(
		const unsigned char *pbCSR, unsigned int ulCSRLen,
		const unsigned char * pbPrivateKey,unsigned int ulPrivateKeyLen,
		unsigned int ulAlg,
		unsigned char *pbCSRSigned, unsigned int * puiCSRSignedLen);

	/*
	��������:	��CRL����ǩ��
	��������:	OpenSSL_GMECC512SignCRL
	�������:	pbCRL					��ǩ��CRL����
				ulCRLLen					��ǩ��CRL����
				pbPublicKeyX				ǩ���߹�ԿX
				pbPublicKeyY				ǩ���߹�ԿY
				pbPrivateKey				˽Կ����
				ulPrivateKeyLen				˽Կ����
	�������:   pbCRLSigned				ǩ��CRL����
				pulCRLSignedLen			ǩ��CRL����
	����ֵ:   
	ʧ�ܣ�
	��������:	��CRL����ǩ��
	*/
	COMMON_API unsigned int OpenSSL_GMECC512SignCRL(
		const unsigned char *pbCRL, unsigned int ulCRLLen,unsigned int ulAlg,
		const unsigned char *pbPublicKeyX, unsigned int ulPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int ulPublicKeyYLen,
		const unsigned char * pbPrivateKey,unsigned int ulPrivateKeyLen,
		unsigned char *pbCRLSigned, unsigned int * puiCRLSignedLen
		);

	/*
	��������:	����Ϣ����ǩ��
	��������:	OpenSSL_GMECC512SignMSG
	�������:	pbMSG						��ǩ������
				ulMSGLen					��ǩ������
				pbPublicKeyX				ǩ���߹�ԿX
				pbPublicKeyY				ǩ���߹�ԿY
				pbPrivateKey				˽Կ����
				ulPrivateKeyLen				˽Կ����
	�������:   pbCRLSigned				ǩ��CRL����
				pulCRLSignedLen			ǩ��CRL����
	����ֵ:   
	ʧ�ܣ�
	��������:	����Ϣ����ǩ��
	*/
	COMMON_API unsigned int OpenSSL_GMECC512SignMSG(const unsigned char *pbMSG, unsigned int ulMSGLen, 
		const unsigned char *pbPublicKeyX, unsigned int ulPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int ulPublicKeyYLen,
		const unsigned char * pbPrivateKey,unsigned int ulPrivateKeyLen,
		unsigned int ulAlg,
		unsigned char *pbSig, unsigned int * puiSigLen);
	/*
	��������:	��HASH����ǩ��
	��������:	OpenSSL_GMECC512SignMSG
	�������:	pbHash						��ǩ��hash����
				ulHashLen					��ǩ��hash����
				pbPublicKeyX				ǩ���߹�ԿX
				pbPublicKeyY				ǩ���߹�ԿY
				pbPrivateKey				˽Կ����
				ulPrivateKeyLen				˽Կ����
	�������:   pbCRLSigned				ǩ��CRL����
				pulCRLSignedLen			ǩ��CRL����
	����ֵ:   
	ʧ�ܣ�
	��������:	��HASH����ǩ��
	*/
	COMMON_API unsigned int OpenSSL_GMECC512SignDigest(const unsigned char *pbHash, unsigned int ulHashLen, 
		const unsigned char *pbPrivateKey, unsigned int ulPrivateKeyLen,
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
		const unsigned char *pbX509, unsigned int ulX509Len,
		X509_TYPE ulX509Type,
		const unsigned char *pbR, unsigned int ulRLen,
		const unsigned char *pbS, unsigned int ulSLen,
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
		const unsigned char *pbX509, unsigned int ulX509Len,
		X509_TYPE ulX509Type,
		unsigned char *pbX509Content, unsigned int *pulX509ContentLen
		);

	/*
	��������:	��֤GMECC512ǩ��
	��������:	OpenSSL_GMECC512VerifyDigest
	�������:	pbHash		HASH����
				ulHashLen			HASH����
				pbSig			ǩ������
				ulSigLen				ǩ������
				pbPublicKeyX		��ԿX����
				ulPublicKeyXLen			��ԿX����
				pbPublicKeyY		��ԿY����
				ulPublicKeyYLen			��ԿY����
	�������:
	����ֵ:   
	ʧ�ܣ�
	��������:	��֤GMECC512ǩ��
	*/
	COMMON_API unsigned int OpenSSL_GMECC512VerifyDigest(const unsigned char *pbHash, unsigned int ulHashLen, 
		const unsigned char *pbSig, unsigned int ulSigLen,
		const unsigned char *pbPublicKeyX, unsigned int ulPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int ulPublicKeyYLen);

	/*
	��������:	��֤ǩ��
	��������:	OpenSSL_GMECC512VerifyMSG
	�������:	pbMSG				ԭ������
				ulMSGLen					ԭ�ĳ���
				pbSig				ǩ��ֵ����
				ulSigLen					ǩ��ֵ����
				pbPublicKeyX			��ԿX����
				ulPublicKeyXLen				��ԿX����
				pbPublicKeyY			��ԿY����
				ulPublicKeyYLen				��ԿY����
	�������:   
	����ֵ:   
	ʧ�ܣ�
	��������:	��֤ǩ��
	*/
	COMMON_API unsigned int OpenSSL_GMECC512VerifyMSG(const unsigned char *pbMSG, unsigned int ulMSGLen, 
		const unsigned char *pbSig, unsigned int ulSigLen,
		const unsigned char *pbPublicKeyX, unsigned int ulPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int ulPublicKeyYLen);

	/*
	��������:	��֤����
	��������:	OpenSSL_GMECC512VerifyCSR
	�������:	pbIN				��������
				ulINLen					���󳤶�
				pbSig				ǩ��ֵ����
				ulSigLen					ǩ��ֵ����
	�������:   
	����ֵ:   
	ʧ�ܣ�
	��������:	��֤����
	*/
	COMMON_API unsigned int OpenSSL_GMECC512VerifyCSR(
		const unsigned char *pbCSR, unsigned int ulCSRLen,
		unsigned int ulAlg
		);

	/*
	��������:	��֤֤��
	��������:	OpenSSL_GMECC512VerifyCert
	�������:	pbX509Cert			֤������
				ulX509CertLen				֤�鳤��
				pbPublicKeyX			��ԿX����
				ulPublicKeyXLen				��ԿX����
				pbPublicKeyY			��ԿY����
				ulPublicKeyYLen				��ԿY����
	�������:   
	����ֵ:   
	ʧ�ܣ�
	��������:	��֤֤��
	*/
	COMMON_API unsigned int OpenSSL_GMECC512VerifyCert(
		const unsigned char *pbX509Cert, unsigned int ulX509CertLen,unsigned int ulAlg,
		const unsigned char *pbPublicKeyX, unsigned int ulPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int ulPublicKeyYLen
		);

	/*
	��������:	��֤CRL
	��������:	OpenSSL_GMECC512VerifyCRL
	�������:	pbCRL					CRL����
				ulCRLLen				CRL����
				pbPublicKeyX			��ԿX����
				ulPublicKeyXLen			��ԿX����
				pbPublicKeyY			��ԿY����
				ulPublicKeyYLen			��ԿY����
	�������:   
	����ֵ:   
	ʧ�ܣ�
	��������:	��֤֤��
	*/
	COMMON_API unsigned int OpenSSL_GMECC512VerifyCRL(
		const unsigned char *pbCRL, unsigned int ulCRLLen,unsigned int ulAlg,
		const unsigned char *pbPublicKeyX, unsigned int ulPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned int ulPublicKeyYLen
		);

	/*
	��������:	GMECC512����
	*/
	COMMON_API unsigned int OpenSSL_GMECC512Decrypt(
		const unsigned char * pbPrivateKey, unsigned int ulPrivateKeyLen, 
		const unsigned char * pbIN, unsigned int ulINLen,
		unsigned char * pbOUT, unsigned int * puiOUTLen
		);
	/*
	��������:	GMECC512����
	*/
	COMMON_API unsigned int OpenSSL_GMECC512Encrypt(
		const unsigned char * pbPublicKeyX, unsigned int ulPublicKeyXLen, 
		const unsigned char * pbPublicKeyY, unsigned int ulPublicKeyYLen,
		const unsigned char * pbIN, unsigned int ulINLen,
		unsigned char * pbOUT, unsigned int * puiOUTLen);

	/*
	��������:	��֤GMECC512��
	*/
	COMMON_API unsigned int OpenSSL_GMECC512Point(
		const unsigned char * pbPublicKeyX, unsigned int ulPublicKeyXLen, 
		const unsigned char * pbPublicKeyY, unsigned int ulPublicKeyYLen
		);


	/*
	��������:	GMECC512����
	*/
	COMMON_API unsigned int OpenSSL_GMECC512DecryptInner(
		const unsigned char *pbIN, unsigned int ulINLen, 
		const unsigned char *pbPrivateKey, unsigned int ulPrivateKeyLen, 
		unsigned char *pbOUT, unsigned int * puiOUTLen
		);

	/*
	��������:	GMECC512����
	*/
	COMMON_API unsigned int OpenSSL_GMECC512EncryptInner(
		const unsigned char *pbIN, unsigned int ulINLen, 
		const unsigned char *pbPublicKeyX, unsigned int ulPublicKeyXLen, 
		const unsigned char *pbPublicKeyY, unsigned int ulPublicKeyYLen, 
		unsigned char *pbOUT, unsigned int * puiOUTLen
		);

	COMMON_API unsigned int OpenSSL_SM2GenPKCS11();


	// GM_ECC_512 end 
#endif

#ifdef __cplusplus
}
#endif


#endif /*_OPENSSL_FUNC_DEF_H_*/