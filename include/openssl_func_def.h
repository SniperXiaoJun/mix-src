
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
	COMMON_API unsigned long OpenSSL_Initialize();

	/*
	��������:	�ͷ���Դ
	��������:	OpenSSL_Finalize
	�������:	
	�������:	
	����ֵ:   
	ʧ�ܣ�
	��������:	�ͷ���Դ
	*/
	COMMON_API unsigned long OpenSSL_Finalize();

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
	COMMON_API unsigned long OpenSSL_SM2GenKeys(unsigned char * pbPublicKeyX,  unsigned long * pulPublicKeyXLen, 
		unsigned char * pbPublicKeyY,  unsigned long * pulPublicKeyYLen,
		unsigned char * pbPrivateKey,  unsigned long * pulPrivateKeyLen);


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
	COMMON_API unsigned long OpenSSL_SM2GenCSRWithPubkey(const OPST_USERINFO *pstUserInfo,
		const unsigned char * pbPublicKeyX,  unsigned long ulPublicKeyXLen, 
		const unsigned char * pbPublicKeyY,  unsigned long ulPublicKeyYLen,
		unsigned char * pbCSR,  unsigned long * pulCSRLen);

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
	COMMON_API unsigned long OpenSSL_SM2GenRootCert(const unsigned char * pbCSR,unsigned long ulCSRLen, unsigned long ulSerialNumber,
		unsigned long ulNotBefore, unsigned long ulNotAfter, 
		unsigned char * pbX509Cert, unsigned long * pulX509CertLen);

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
	COMMON_API unsigned long OpenSSL_SM2GenCert(const unsigned char * pbCSR,unsigned long ulCSRLen, 
		const unsigned char * pbX509CACert, unsigned long ulX509CACertLen, 
		unsigned long ulSerialNumber,
		unsigned long ulNotBefore, unsigned long ulNotAfter, unsigned long ulSignFlag,
		unsigned char * pbX509Cert, unsigned long * pulX509CertLen);
	
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
	COMMON_API unsigned long OpenSSL_SM2GenCertEX(const unsigned char * pbCSR,unsigned long ulCSRLen, 
		const unsigned char * pbPublicKeyX, unsigned long ulPublicKeyXLen, 
		const unsigned char * pbPublicKeyY, unsigned long ulPublicKeyYLen,
		const unsigned char * pbX509CACert, unsigned long ulX509CACertLen, 
		unsigned long ulSerialNumber,
		unsigned long ulNotBefore, unsigned long ulNotAfter, unsigned long ulSignFlag,
		unsigned char * pbX509Cert, unsigned long * pulX509CertLen);

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
	COMMON_API unsigned long OpenSSL_SM2GenCRL(const OPST_CRL * pstCRLList, unsigned long ulCRLListSize, 
		const unsigned char * pbX509Cert,unsigned long ulX509CertLen, 
		unsigned char * pbCRL, unsigned long * pulCRLLen);

	
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
	COMMON_API unsigned long OpenSSL_SM2SignCert(
		const unsigned char *pbX509Cert,  unsigned long ulX509CertLen, 
		const unsigned char *pbPublicKeyX, unsigned long ulPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned long ulPublicKeyYLen,
		const unsigned char *pbPrivateKey,  unsigned long ulPrivateKeyLen,
		unsigned char * pbX509CertSigned,  unsigned long * pulX509CertSignedLen
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
	COMMON_API unsigned long OpenSSL_SM2SignCSR(
		const unsigned char *pbCSR, unsigned long ulCSRLen,
		const unsigned char * pbPrivateKey,unsigned long ulPrivateKeyLen,
		unsigned long ulAlg,
		unsigned char *pbCSRSigned, unsigned long * pulCSRSignedLen);

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
	COMMON_API unsigned long OpenSSL_SM2SignCRL(
		const unsigned char *pbCRL, unsigned long ulCRLLen,unsigned long ulAlg,
		const unsigned char *pbPublicKeyX, unsigned long ulPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned long ulPublicKeyYLen,
		const unsigned char * pbPrivateKey,unsigned long ulPrivateKeyLen,
		unsigned char *pbCRLSigned, unsigned long * pulCRLSignedLen
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
	COMMON_API unsigned long OpenSSL_SM2SignMSG(const unsigned char *pbMSG, unsigned long ulMSGLen, 
		const unsigned char *pbPublicKeyX, unsigned long ulPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned long ulPublicKeyYLen,
		const unsigned char * pbPrivateKey,unsigned long ulPrivateKeyLen,
		unsigned long ulAlg,
		unsigned char *pbSig, unsigned long * pulSigLen);
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
	COMMON_API unsigned long OpenSSL_SM2SignDigest(const unsigned char *pbHash, unsigned long ulHashLen, 
		const unsigned char *pbPrivateKey, unsigned long ulPrivateKeyLen,
		unsigned char *pbSig, unsigned long * pulSigLen
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
	COMMON_API unsigned long OpenSSL_SM2SetX509SignValue(
		const unsigned char *pbX509, unsigned long ulX509Len,
		X509_TYPE ulX509Type,
		const unsigned char *pbR, unsigned long ulRLen,
		const unsigned char *pbS, unsigned long ulSLen,
		unsigned char *pbX509Signed, unsigned long * pulX509SignedLen);
	
	/*
	��������:	��ȡX509���ݣ�������ǩ��ֵ��
	��������:	OpenSSL_SM2SetX509SignValue
	�������:	
	�������:   
	����ֵ:   
	ʧ�ܣ�
	��������:	��ȡX509���ݣ�������ǩ��ֵ��
	*/
	COMMON_API unsigned long OpenSSL_GetX509Content(
		const unsigned char *pbX509, unsigned long ulX509Len,
		X509_TYPE ulX509Type,
		unsigned char *pbX509Content, unsigned long *pulX509ContentLen
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
	COMMON_API unsigned long OpenSSL_SM2VerifyDigest(const unsigned char *pbHash, unsigned long ulHashLen, 
		const unsigned char *pbSig, unsigned long ulSigLen,
		const unsigned char *pbPublicKeyX, unsigned long ulPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned long ulPublicKeyYLen);

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
	COMMON_API unsigned long OpenSSL_SM2VerifyMSG(const unsigned char *pbMSG, unsigned long ulMSGLen, 
		const unsigned char *pbSig, unsigned long ulSigLen,
		const unsigned char *pbPublicKeyX, unsigned long ulPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned long ulPublicKeyYLen);

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
	COMMON_API unsigned long OpenSSL_SM2VerifyCSR(
		const unsigned char *pbCSR, unsigned long ulCSRLen,
		unsigned long ulAlg
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
	COMMON_API unsigned long OpenSSL_SM2VerifyCert(
		const unsigned char *pbX509Cert, unsigned long ulX509CertLen,unsigned long ulAlg,
		const unsigned char *pbPublicKeyX, unsigned long ulPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned long ulPublicKeyYLen
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
	COMMON_API unsigned long OpenSSL_SM2VerifyCRL(
		const unsigned char *pbCRL, unsigned long ulCRLLen,unsigned long ulAlg,
		const unsigned char *pbPublicKeyX, unsigned long ulPublicKeyXLen,
		const unsigned char *pbPublicKeyY, unsigned long ulPublicKeyYLen
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
	COMMON_API unsigned long OpenSSL_CertGetSubject(
		const unsigned char * pbX509Cert, unsigned long ulX509CertLen,
		unsigned char * pbSubject, unsigned long * pulSubjectLen
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
	COMMON_API unsigned long OpenSSL_CertGetPubkey(
		const unsigned char * pbX509Cert, unsigned long ulX509CertLen,
		unsigned char * pbPublicKey, unsigned long * pulPublicKeyLen);

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
	COMMON_API unsigned long OpenSSL_CertGetSubjectItem(
		const unsigned char * pbX509Cert, unsigned long ulX509CertLen,
		int ulIndex, 
		unsigned char * pbSubjectItem, unsigned long * pulSubjectItemLen
		);

	/*
	��������:	SM2����
	*/
	COMMON_API unsigned long OpenSSL_SM2Decrypt(
		const unsigned char * pbPrivateKey, unsigned long ulPrivateKeyLen, 
		const unsigned char * pbIN, unsigned long ulINLen,
		unsigned char * pbOUT, unsigned long * pulOUTLen
		);
	/*
	��������:	SM2����
	*/
	COMMON_API unsigned long OpenSSL_SM2Encrypt(
		const unsigned char * pbPublicKeyX, unsigned long ulPublicKeyXLen, 
		const unsigned char * pbPublicKeyY, unsigned long ulPublicKeyYLen,
		const unsigned char * pbIN, unsigned long ulINLen,
		unsigned char * pbOUT, unsigned long * pulOUTLen);

	/*
	��������:	��֤SM2��
	*/
	COMMON_API unsigned long OpenSSL_SM2Point(
		const unsigned char * pbPublicKeyX, unsigned long ulPublicKeyXLen, 
		const unsigned char * pbPublicKeyY, unsigned long ulPublicKeyYLen
		);

	/*
	��������:	������������ļ�
	*/
	COMMON_API unsigned long OpenSSL_SM2Write(
		const unsigned char * pbIN, unsigned long ulINLen, 
		unsigned long ulType,
		char * szFileName,
		unsigned long fileEncode, char * szPassword
		);

	/*
	��������:	SM2����
	*/
	COMMON_API unsigned long OpenSSL_SM2DecryptInner(
		const unsigned char *pbIN, unsigned long ulINLen, 
		const unsigned char *pbPrivateKey, unsigned long ulPrivateKeyLen, 
		unsigned char *pbOUT, unsigned long * pulOUTLen
		);

	/*
	��������:	SM2����
	*/
	COMMON_API unsigned long OpenSSL_SM2EncryptInner(
		const unsigned char *pbIN, unsigned long ulINLen, 
		const unsigned char *pbPublicKeyX, unsigned long ulPublicKeyXLen, 
		const unsigned char *pbPublicKeyY, unsigned long ulPublicKeyYLen, 
		unsigned char *pbOUT, unsigned long * pulOUTLen
		);

	/*
	��������:	��ȡ֤�鹫Կ�㷨
	*/
	COMMON_API unsigned long OpenSSL_CertGetPublicKeyAlgor(
		const unsigned char * pbX509Cert, unsigned long ulX509CertLen,
		unsigned char *pbPublicKeyAlgor, unsigned long *pulPublicKeyAlgorLen
		);

	/*
	��������:	�Ƚ�֤��İ䷢�ߺ�ʹ����
	*/
	COMMON_API unsigned long OpenSSL_CertSubjectCompareIssuer(const unsigned char * pbX509Cert, unsigned long ulX509CertLen,
		unsigned long * bEqual
		);

	COMMON_API unsigned long OpenSSL_CertExtenItem(const unsigned char * pbX509Cert, unsigned long ulX509CertLen,int ulIndex, unsigned char * pbSubjectItem, unsigned long * pulSubjectItemLen);

#ifdef __cplusplus
}
#endif


#endif /*_OPENSSL_FUNC_DEF_H_*/