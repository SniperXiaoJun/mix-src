




#ifndef _PKCS11_FUNC_DEF_H_
#define _PKCS11_FUNC_DEF_H_

#include "common.h"
#include "o_all_type_def.h"

#ifdef __cplusplus
extern "C" {
#endif
	/*
	��������:	��ʼ����Դ
	��������:	PKCS11_Initialize
	�������:	
	�������:	
	����ֵ:   
	ʧ�ܣ�
	��������:	��ʼ��PKCS11
	*/
	COMMON_API unsigned long PKCS11_Initialize();

	/*
	��������:	�ͷ���Դ
	��������:	PKCS11_Finalize
	�������:	
	�������:	
	����ֵ:   
	ʧ�ܣ�
	��������:	�ͷ���Դ
	*/
	COMMON_API unsigned long PKCS11_Finalize();

	/*
	��������:	ö���豸
	��������:	PKCS11_EnumDevices
	�������:	pszDevicesInfo			�豸����
				pulDevCount		�豸��Ϣ
	�������:	pszDevicesInfo		�豸��Ϣ
				pulDevCount			�豸����
	����ֵ:   
	ʧ�ܣ�
	��������:	ö�ٲ���¼��ǰ�豸
	*/
	COMMON_API unsigned long PKCS11_EnumDevices(OPST_DEV pszDevicesInfo[], unsigned long * pulDevCount);

	/*
	��������:	���豸
	��������:	PKCS11_OpenDevice
	�������:	stDeviceInfo			�豸��Ϣ
	�������:	hHandleDev			�豸���
	����ֵ:   
	ʧ�ܣ�
	��������:	���豸
	*/
	COMMON_API unsigned long PKCS11_OpenDevice(OPST_DEV stDeviceInfo,OPT_HDEVICE * phHandleDev);

	/*
	��������:	�ر��豸
	��������:	PKCS11_CloseDevice
	�������:	hHandleDev			�豸���
	�������:	
	����ֵ:   
	ʧ�ܣ�
	��������:	�ر��豸
	*/
	COMMON_API unsigned long PKCS11_CloseDevice(OPT_HDEVICE hHandleDev);

	/*
	��������:	��¼�豸
	��������:	PKCS11_Login
	�������:	hHandleDev		�豸���
				ulLoginType		�û����� 0:����Ա 1:�û�
				pbPin			����ֵ
				ulPinLen		�����
	�������:	pulRetryTimes	���Դ���
	����ֵ:   
	ʧ�ܣ�
	��������:	��¼��ǰ�豸
	*/
	COMMON_API unsigned long PKCS11_Login(OPT_HDEVICE hHandleDev, unsigned long ulLoginType,
		const unsigned char*pbPin, unsigned long ulPinLen, unsigned long *pulRetryTimes);

	/*
	��������:	ע����¼�豸
	��������:	PKCS11_Logout
	�������:	hHandleDev		�豸���
	�������:	
	����ֵ:   
	ʧ�ܣ�
	��������:	ע����¼��ǰ�豸
	*/
	COMMON_API unsigned long PKCS11_Logout(OPT_HDEVICE hHandleDev);

	/*
	��������:	��������
	��������:	PKCS11_CreateContainer
	�������:	hHandleDev		�豸���
				pbConNameValue	��������
				ulConNameLen		�������Ƴ���
	�������:	
	����ֵ:   
	ʧ�ܣ�
	��������:	��������
	*/
	COMMON_API unsigned long PKCS11_CreateContainer(OPT_HDEVICE hHandleDev,
		const unsigned char * pbConNameValue, unsigned long ulConNameLen);

	/*
	��������:	ɾ������
	��������:	PKCS11_DeleteContainer
	�������:	hHandleDev		�豸���
				pbConNameValue	��������
				ulConNameLen		�������Ƴ���
	�������:	
	����ֵ:   
	ʧ�ܣ�
	��������:	ɾ������
	*/
	COMMON_API unsigned long PKCS11_DeleteContainer(OPT_HDEVICE hHandleDev, 
		const unsigned char * pbConNameValue, unsigned long ulConNameLen);

	/*
	��������:	ö������
	��������:	PKCS11_EnumContainers
	�������:	hHandleDev		�豸���
				pulConCount		��������
				pszContainers     �����ṹ������
	�������:	pulConCount		��������
				pszContainers     �����ṹ�����飨�����������ƺͳ��ȣ�
	����ֵ:   
	ʧ�ܣ�
	��������:	ö������
	*/
	COMMON_API unsigned long PKCS11_EnumContainers(OPT_HDEVICE hHandleDev, OPST_CONTAINER pszContainers[], 
		unsigned long * pulConCount);

	/*
	��������:	��������Ƿ����
	��������:	PKCS11_CheckContainerExist
	�������:	hHandleDev		�豸���
				pbConNameValue	��������		��OPST_CONTAINER �ṹ������������ͳ��ȣ�
				ulConNameLen		����������		��OPST_CONTAINER �ṹ������������ͳ��ȣ�
	�������:	
	����ֵ:   
	ʧ�ܣ�
	��������:	��������Ƿ����
	*/
	COMMON_API unsigned long PKCS11_CheckContainerExist(OPT_HDEVICE hHandleDev, 
		const unsigned char * pbConNameValue, unsigned long ulConNameLen);

	/*
	��������:	������
	��������:	PKCS11_OpenContainer
	�������:	hHandleDev		�豸���
				pbConNameValue	��������		��OPST_CONTAINER �ṹ������������ͳ��ȣ�
				ulConNameLen		����������		��OPST_CONTAINER �ṹ������������ͳ��ȣ�
				ulConType		��Կ���� ����:0  ǩ��:1
	�������:	
				phHandleCon			�������
	����ֵ:   
	ʧ�ܣ�
	��������:	������
	*/
	COMMON_API unsigned long PKCS11_OpenContainer(OPT_HDEVICE hHandleDev,const unsigned char * pbConNameValue, 
		unsigned long ulConNameLen,unsigned long ulConType, OPT_HCONTAINER * phHandleCon);

	/*
	��������:	�ر�����
	��������:	PKCS11_CloseContainer
	�������:	hHandle			�������
	�������:	
	����ֵ:   
	ʧ�ܣ�
	��������:	�ر�����
	*/
	COMMON_API unsigned long PKCS11_CloseContainer(OPT_HCONTAINER hHandle);

	/*
	��������:	����SM2��˽Կ��
	��������:	PKCS11_SM2GenKeys
	�������:	hHandle        �������
	�������:	
	����ֵ:   
	ʧ�ܣ�
	��������:	����SM2��Կ�ԣ�P11��
	*/
	COMMON_API unsigned long PKCS11_SM2GenKeys(OPT_HCONTAINER hHandle);

	/*
	��������:	������Կ
	��������:	PKCS11_SM2ExportKeys
	�������:	hHandle         �������
	�������:	pbPubKeyX		��ԿXֵ
				pulPubKeyLenX		��ԿX����
				pbPubKeyY		��ԿYֵ
				pulPubKeyLenY		��ԿY����
	����ֵ:   
	ʧ�ܣ�
	��������:	������Կ
	*/
	COMMON_API unsigned long PKCS11_SM2ExportKeys(OPT_HCONTAINER hHandle,
		unsigned char *pbPubKeyX, unsigned long *pulPubKeyLenX, unsigned char *pbPubKeyY, 
		unsigned long *pulPubKeyLenY);

	/*
	��������:	����SM2��˽Կ��
	��������:	PKCS11_SM2ImportKeys
	�������:	hHandle			�������
				ulHandleEnDecypt �ӽ����������
				pbPrvkey	˽Կֵ
				ulPrvKeyLen		˽Կ����
				pbPubkeyX		��ԿXֵ
				ulPubkeyXLen		��ԿX����
				pbPubkeyY		��ԿYֵ
				ulPubkeyYLen		��ԿY����
	�������:	
	����ֵ:   
	ʧ�ܣ�
	��������:	��SM2��˽Կ���뵽����
	*/
	COMMON_API unsigned long PKCS11_SM2ImportKeys(OPT_HCONTAINER hHandle,OPT_HCONTAINER ulHandleEnDecypt, 
		const unsigned char * pbPrvkey, unsigned long ulPrvKeyLen, 
		const unsigned char * pbPubkeyX, unsigned long ulPubkeyXLen, 
		const unsigned char * pbPubkeyY, unsigned long ulPubkeyYLen);


	/*
	��������:	����֤��
	��������:	PKCS11_CertImport
	�������:	hHandle				�������
				pbCert			֤������
				ulCertLen				֤�鳤��
				pbSubject	��������
				ulSubjectLen		���ⳤ��
	�������:	
	����ֵ:   
	ʧ�ܣ�
	��������:	��֤�鵼�뵽����
	*/
	COMMON_API unsigned long PKCS11_CertImport(OPT_HCONTAINER hHandle,
		const unsigned char * pbCert, unsigned long ulCertLen,
		const unsigned char * pbSubject, unsigned long ulSubjectLen);

	/*
	��������:	����֤��
	��������:	PKCS11_CertExport
	�������:	hHandle			�������
	�������:	pbCert		֤������
				pulCertLen		֤�鳤��
	����ֵ:   
	ʧ�ܣ�
	��������:	��֤�����������
	*/
	COMMON_API unsigned long PKCS11_CertExport(OPT_HCONTAINER hHandle, unsigned char * pbCert, unsigned long * pulCertLen);

	/*
	��������:	ǩ����Ϣ
	��������:	PKCS11_SignMSG
	�������:	hHandle			�������
				pbIn		ԭ��ֵ
				ulInLen			ԭ�ĳ���
				ulAlg			�㷨
	�������:	pbSigValue		ǩ������
				pulSigLen		ǩ������
	����ֵ:   
	ʧ�ܣ�
	��������:	ǩ����Ϣ
	*/
	COMMON_API unsigned long PKCS11_SM2SignMSG(OPT_HCONTAINER hHandle,
		const unsigned char *pbIn, unsigned long ulInLen,unsigned long ulAlg,
		unsigned char * pbSigValue, unsigned long * pulSigLen);


	/*
	��������:	��֤��Ϣ
	��������:	PKCS11_VerifyMSG
	�������:	hHandle			�������
				pbMsg		ԭ��ֵ
				ulMsgLen		ԭ�ĳ���
				ulAlg			�㷨
				pbSigValue		ǩ������
				ulSigLen		ǩ������
	�������:
	����ֵ:   
	ʧ�ܣ�
	��������:	��֤��Ϣ
	*/
	COMMON_API unsigned long PKCS11_SM2VerifyMSG(OPT_HCONTAINER hHandle,
		const unsigned char *pbMsg, unsigned long ulMsgLen,unsigned long ulAlg,
		const unsigned char *pbSigValue, unsigned long ulSigLen );

#ifdef __cplusplus
}
#endif




#endif/*_PKCS11_FUNC_DEF_H_*/


