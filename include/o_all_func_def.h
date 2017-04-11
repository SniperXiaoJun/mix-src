
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
	COMMON_API unsigned int OPF_Initialize();
	
	/*
	��������:	�ͷ���Դ
	��������:	OPF_Finalize
	�������:	
	�������:	
	����ֵ:   
	ʧ�ܣ�
	��������:	����ȫ�ֱ������ر�P11_SESSION|OPEN_SSL
	*/
	COMMON_API unsigned int OPF_Finalize();

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
	COMMON_API unsigned int OPF_CertImport(OPT_HCONTAINER hContainer, 
		const unsigned char * pbX509Cert, unsigned int uiX509CertLen);

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
	COMMON_API unsigned int OPF_SM2GenCSR(OPT_HCONTAINER hContainer,
		const OPST_USERINFO *pstUserInfo,unsigned char * pbCSR, unsigned int * puiCSRLen);

	/*
	��������:	ǩ��֤������
	��������:	OPF_SignCSR
	�������:	aHandle			˽Կ�������
				ain_value_csr   ����ֵ
				ain_len_csr		���󳤶�
	�������:	aout_value		ǩ������
				aout_len		ǩ������
				uiAlg			�㷨
	����ֵ:   
	ʧ�ܣ�
	��������:	ǩ��֤������
	*/
	COMMON_API unsigned int OPF_SM2SignCSR(OPT_HCONTAINER hContainer,
		const unsigned char *pbCSR, unsigned int uiCSR,unsigned int uiAlg,
		unsigned char * pbCSRSigned, unsigned int * puiCSRSignedLen);

	/*
	��������:	ǩ��֤��
	��������:	OPF_SM2SignCert
	�������:	hSessionHandle			PCI���
				pbX509Cert   ֤��ֵ
				uiX509CertLen	֤�鳤��
				uiAlg			�㷨
	�������:	pbX509CertSigned		ǩ������֤������
				puiX509CertSignedLen		ǩ������֤�鳤��
	����ֵ:   
	ʧ�ܣ�
	��������:	ǩ��֤��
	*/
	COMMON_API unsigned int OPF_SM2SignCert(void * hSessionHandle,
		const unsigned char *pbX509Cert, unsigned int uiX509CertLen,unsigned int uiAlg,
		unsigned char * pbX509CertSigned, unsigned int * puiX509CertSignedLen);

	/*
	��������:	ǩ��CRL
	��������:	OPF_SM2SignCert
	�������:	hSessionHandle			PCI���
				pbX509Cert   						֤��ֵ
				uiX509CertLen						֤�鳤��
				pbCRL										CRL����
				uiCRL										CRL����
				uiAlg									�㷨
	�������:	pbCRLSigned				ǩ������CRL����
				puiCRLSigned					ǩ������CRL����
	����ֵ:   
	ʧ�ܣ�
	��������:	ǩ��CRL
	*/
	COMMON_API unsigned int OPF_SM2SignCRL(void * hSessionHandle,
		const unsigned char *pbX509Cert, unsigned int uiX509CertLen,
		const unsigned char *pbCRL, unsigned int uiCRL,unsigned int uiAlg,
		unsigned char * pbCRLSigned, unsigned int * puiCRLSigned);


	// ��������HEX�໥ת��
	COMMON_API unsigned int OPF_Str2Bin(const char *pbIN,unsigned int uiIN,unsigned char *pbOUT,unsigned int * puiOUT);
	// ��������HEX�໥ת��
	COMMON_API unsigned int OPF_Bin2Str(const unsigned char *pbIN, unsigned int uiINLen, char *pbOUT, unsigned int * puiOUTLen);
		
		
#if defined(UNICODE)
#include <Windows.h>
	COMMON_API unsigned int OPF_WStr2Bin(const wchar_t *pbIN,unsigned int uiINLen,unsigned char *pbOUT,unsigned int * puiOUTLen);
	COMMON_API unsigned int OPF_Bin2WStr(const unsigned char *pbIN, unsigned int uiINLen, wchar_t *pbOUT, unsigned int * puiOUTLen);
#endif		
		

	// �����б����
	COMMON_API unsigned int OPF_AddMallocedHandleNodeDataToLink(OPST_HANDLE_NODE * * ppstHeader, void * pvNodeData);
	COMMON_API unsigned int OPF_DelAndFreeHandleNodeDataFromLink(OPST_HANDLE_NODE * * ppstHeader,  void * pvNodeData);
	COMMON_API unsigned int OPF_CheckExistHandleNodeDataFromLink(OPST_HANDLE_NODE * * ppstHeader,  void * pvNodeData);
	COMMON_API unsigned int OPF_ClearExistHandleNodeDataFromLink(OPST_HANDLE_NODE * * ppstHeader);

#ifdef __cplusplus
}
#endif

#endif/* end _O_ALL_FUNC_DEF_H_*/
