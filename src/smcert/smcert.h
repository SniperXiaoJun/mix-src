#ifndef __SMCERT_H
#define __SMCERT_H

#define STDCALL __stdcall

#if 1		//֤����Ϣ���
//����壬iNameID
#define CERT_VERSION				1		//Version					֤��汾
#define CERT_SERIALNUMBER			2		//SerialNumber				֤�����к�
#define CERT_SIGNATUREALGORITHM		3		//SignatureAlgorithm		ǩ���㷨
#define CERT_NOTBEFORE				4		//NotBefore					��Ч��ʼ����
#define CERT_NOTAFTER				5		//NotAfter					��Ч��ֹ����
#define CERT_SUBJECTPUBLICKEYINFO	6		//SubjectPublicKeyInfo		��Կֵ
#define CERT_ISSUER_DN				7		//Issuer					�䷢��
#define CERT_SUBJECT_DN				8		//Subject					����
#define CERT_KEYUSAGE				9		//Keyusage					��Կ�÷�

#define CERT_PURPOSE				10		//certpurpose				֤��Ŀ��

//����壬iSubNameID
#define NID_COMMONNAME				13		//"commonName""CN"
#define NID_COUNTRYNAME				14		//"countryName" "C"
#define NID_LOCALITYNAME			15		//"localityName" "L"
#define NID_STATEORPROVINCENAME		16		//"stateOrProvinceName" "ST"
#define NID_ORGANIZATIONNAME		17		//"organizationName" "O"
#define NID_ORGANIZATIONALUNITNAME	18		//"organizationalUnitName" "OU"
#define NID_PKCS9_EMAILADDRESS		48		//"emailAddress" "E"

#endif

//---------------------------------------------------------------------------------------
//�����붨��
#define	WT_OK							0x00000000		//�ɹ�

#define	WT_ERR							0x0E000000		//ʧ��
#define	WT_ERR_UNKNOWNERR				(WT_ERR+1)		//δ֪�쳣����
#define	WT_ERR_INVALIDPARAM				(WT_ERR+2)		//��Ч�Ĳ���

#define	WT_ERR_FILE						(WT_ERR+3)		//�ļ���������
#define	WT_ERR_READFILE					(WT_ERR+4)		//���ļ�����
#define	WT_ERR_WRITEFILE				(WT_ERR+5)		//д�ļ�����

#define	WT_ERR_MEMORY					(WT_ERR+6)		//�ڴ����
#define	WT_ERR_BUFFER_TOO_SMALL			(WT_ERR+7)		//����������
//---------------------------------------------------------------------------------------

#ifdef __cplusplus
extern "C" {
#endif

//���ܣ�����֤��,֧��PEM�Լ�DER��ʽ
//������pbMyCert��	֤������
//		ulCertLen��	֤�����ݳ���
int STDCALL WT_SetMyCert(unsigned char *pbMyCert, unsigned long ulCertLen);

//���ܣ���ȡ֤����Ϣ
//������iNameID��	֤����Ϣ����Ϻ궨��CERT_XXXX
//	    iSubNameID��֤����Ϣ�����iNameID=CERT_ISSUER_DN��CERT_SUBJECT_DNʱ��������Ч, ����Ĭ��Ϊ-1, 
//					��������Чʱ����ȡֵ���Ϻ궨��NID_XXX��
//		pszGB��		�����ַ�����  ��iNameID=CERT_ISSUER_DN��CERT_SUBJECT_DNʱ���ַ�����"/"��Ϊ�ָ�����
//		piLen��		�����ַ������ȣ���ֵpszGBΪNULLʱ�����������Է�����Ҫ�Ļ��泤�ȡ�
//��ע������Ԥ�ȵ���WT_SetMyCert
int STDCALL WT_GetCertInfo(int iNameID, int iSubNameID, char *pszGB, int* piLen);

//���ܣ������ǰ���õ�֤��
int STDCALL WT_ClearCert();

#ifdef __cplusplus
}
#endif

#endif //__SMCERT_H