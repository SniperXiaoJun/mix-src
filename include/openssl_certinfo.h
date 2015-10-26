

#ifndef __OPENSSL_CERT_PRASE__
#define __OPENSSL_CERT_PRASE__

#include "common.h"


typedef enum ECERT_INFO
{
	ECERT_INFO_VERSION,			// �汾
	ECERT_INFO_SN,				// ���к�
	ECERT_INFO_ISSUER,			// �䷢��
	ECERT_INFO_NOTBEFORE,		// ��Ч�ڴ�
	ECERT_INFO_NOTAFTER,		// ��Ч�ڵ�
	ECERT_INFO_NAME,			// ʹ����
	ECERT_INFO_PUBKEY,			// ��Կ
	ECERT_INFO_SIG_ALG,			// ǩ���㷨
	ECERT_INFO_KEYUSAGE,		// ��Կ�÷�
	ECERT_INFO_PURPOSE,			// ֤��Ŀ��

	ECERT_INFO_EXTENSION,       // ��չ��Ϣ
	ECERT_INFO_SIG,				// ǩ��ֵ
	ECERT_INFO_SIG_INNER,		// ǩ��ֵ(��)
};

typedef enum ECERT_INFO_SUB
{
	//����壬iSubNameID
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
	���ܣ�����֤��,֧��PEM�Լ�DER��ʽ
	������data_value_cert��	֤������
		  data_len_cert��		֤�����ݳ���
	*/
	int COMMON_API OpenSSL_PraseCertInitialize(const unsigned char * pbX509Cert, unsigned long ulX509CertLen);

	//���ܣ���ȡ֤����Ϣ
	//������iNameID��	֤����Ϣ����Ϻ궨��CERT_XXXX
	//	    iSubNameID��֤����Ϣ�����iNameID=CERT_ISSUER_DN��CERT_SUBJECT_DNʱ��������Ч, ����Ĭ��Ϊ-1, 
	//					��������Чʱ����ȡֵ���Ϻ궨��NID_XXX��
	//		pszGB��		�����ַ�����  ��iNameID=CERT_ISSUER_DN��CERT_SUBJECT_DNʱ���ַ�����"/"��Ϊ�ָ�����
	//		piLen��		�����ַ������ȣ���ֵpszGBΪNULLʱ�����������Է�����Ҫ�Ļ��泤�ȡ�
	//��ע������Ԥ�ȵ���WT_SetMyCert
	int COMMON_API OpenSSL_PraseCertInfo(int iNameID, int iSubNameID, char *pszGB, int* piLen);

	//���ܣ������ǰ���õ�֤��
	int COMMON_API OpenSSL_PraseCertFinalize();


#ifdef __cplusplus
}
#endif


#endif