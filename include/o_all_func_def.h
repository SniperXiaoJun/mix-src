
#ifndef _O_ALL_FUNC_DEF_H_
#define _O_ALL_FUNC_DEF_H_

#include "common.h"

#include "o_all_type_def.h"		// ���Ͷ���

#ifdef __cplusplus
extern "C" {
#endif
	/*
	��������:	��ʼ����Դ
	��������:	OPF_Initialize
	�������:	
	�������:	
	����ֵ:   
	ʧ�ܣ�
	��������:	��ʼ����Դȫ�ֱ�������P11_SESSION|OPEN_SSL
	*/
	COMMON_API unsigned long OPF_Initialize();
	
	/*
	��������:	�ͷ���Դ
	��������:	OPF_Finalize
	�������:	
	�������:	
	����ֵ:   
	ʧ�ܣ�
	��������:	����ȫ�ֱ������ر�P11_SESSION|OPEN_SSL
	*/
	COMMON_API unsigned long OPF_Finalize();

	/*
	��������:	����֤��
	��������:	OPF_CertImport
	�������:	aDevInfo        �豸
				ain_value		֤������
				ain_len			֤�鳤��
	�������:	
	����ֵ:   
	ʧ�ܣ�
	��������:	��֤�鵼�뵽����
	*/
	COMMON_API unsigned long OPF_CertImport(OPT_HCONTAINER hContainer, 
		const unsigned char * pbX509Cert, unsigned long ulX509CertLen);

	/*
	��������:	������SM2��Կ������֤������
	��������:	OPF_SM2GenCSR
	�������:	aHandle         �������
				info			�û���Ϣ
	�������:	aout_value		֤������
				aout_len		֤�鳤��
	����ֵ:   
	ʧ�ܣ�
	��������:	������SM2��Կ������֤������
	*/
	COMMON_API unsigned long OPF_SM2GenCSR(OPT_HCONTAINER hContainer,
		const OPST_USERINFO *pstUserInfo,unsigned char * pbCSR, unsigned long * pulCSRLen);

	/*
	��������:	ǩ��֤������
	��������:	OPF_SignCSR
	�������:	aHandle			˽Կ�������
				ain_value_csr   ����ֵ
				ain_len_csr		���󳤶�
	�������:	aout_value		ǩ������
				aout_len		ǩ������
				ulAlg			�㷨
	����ֵ:   
	ʧ�ܣ�
	��������:	ǩ��֤������
	*/
	COMMON_API unsigned long OPF_SM2SignCSR(OPT_HCONTAINER hContainer,
		const unsigned char *pbCSR, unsigned long ulCSR,unsigned long ulAlg,
		unsigned char * pbCSRSigned, unsigned long * pulCSRSignedLen);

	/*
	��������:	ǩ��֤��
	��������:	OPF_SM2SignCert
	�������:	hSessionHandle			PCI���
				pbX509Cert   ֤��ֵ
				ulX509CertLen	֤�鳤��
				ulAlg			�㷨
	�������:	pbX509CertSigned		ǩ������֤������
				pulX509CertSignedLen		ǩ������֤�鳤��
	����ֵ:   
	ʧ�ܣ�
	��������:	ǩ��֤��
	*/
	COMMON_API unsigned long OPF_SM2SignCert(void * hSessionHandle,
		const unsigned char *pbX509Cert, unsigned long ulX509CertLen,unsigned long ulAlg,
		unsigned char * pbX509CertSigned, unsigned long * pulX509CertSignedLen);

	/*
	��������:	ǩ��CRL
	��������:	OPF_SM2SignCert
	�������:	hSessionHandle			PCI���
				pbX509Cert   						֤��ֵ
				ulX509CertLen						֤�鳤��
				pbCRL										CRL����
				ulCRL										CRL����
				ulAlg									�㷨
	�������:	pbCRLSigned				ǩ������CRL����
				pulCRLSigned					ǩ������CRL����
	����ֵ:   
	ʧ�ܣ�
	��������:	ǩ��CRL
	*/
	COMMON_API unsigned long OPF_SM2SignCRL(void * hSessionHandle,
		const unsigned char *pbX509Cert, unsigned long ulX509CertLen,
		const unsigned char *pbCRL, unsigned long ulCRL,unsigned long ulAlg,
		unsigned char * pbCRLSigned, unsigned long * pulCRLSigned);


	// ��������HEX�໥ת��
	COMMON_API unsigned long OPF_Str2Bin(const char *pbIN,unsigned long ulIN,unsigned char *pbOUT,unsigned long * pulOUT);
	// ��������HEX�໥ת��
	COMMON_API unsigned long OPF_Bin2Str(const unsigned char *ain_data_value,unsigned long ain_data_len,
		char *aout_data_value,unsigned long * aout_data_len);

	// �����б����
	COMMON_API unsigned long OPF_AddMallocedHandleNodeDataToLink(OPST_HANDLE_NODE * * ppstHeader, void * pvNodeData);
	COMMON_API unsigned long OPF_DelAndFreeHandleNodeDataFromLink(OPST_HANDLE_NODE * * ppstHeader,  void * pvNodeData);
	COMMON_API unsigned long OPF_CheckExistHandleNodeDataFromLink(OPST_HANDLE_NODE * * ppstHeader,  void * pvNodeData);
	COMMON_API unsigned long OPF_ClearExistHandleNodeDataFromLink(OPST_HANDLE_NODE * * ppstHeader);

#ifdef __cplusplus
}
#endif

#endif/* end _O_ALL_FUNC_DEF_H_*/
