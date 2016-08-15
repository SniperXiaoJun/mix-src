


#ifndef PCI_FUNC_DEF_H_
#define PCI_FUNC_DEF_H_

#include "common.h"

#include "swsds.h"

typedef void * HANDLE;

#ifdef __cplusplus
extern "C" {
#endif


	/*
	��������:	���ɲ�����SM2������Կ�����ŷ�
	��������:	PCI_GenExportSM2EnvelopedKey
	�������:	hSessionHandle			�Ự���
				pbPubkeyX				�ⲿǩ����ԿX�����ȱ���Ϊ32��
				pbPubkeyY				�ⲿǩ����ԿY�����ȱ���Ϊ32��
	�������:	pvENVELOPEDKEYBLOB_IPK	�ڲ���Կ���ܵ�ECC��Կ�������ŷ�(����ΪOPST_SKF_ENVELOPEDKEYBLOB)
				pvENVELOPEDKEYBLOB_EPK	�ⲿ��Կ���ܵ�ECC��Կ�������ŷ�(����ΪOPST_SKF_ENVELOPEDKEYBLOB)
	����ֵ:   
	ʧ�ܣ�
	��������:	���ɲ�����SM2������Կ�����ŷ�
	*/
	COMMON_API unsigned int PCI_GenExportSM2EnvelopedKey(HANDLE hSessionHandle, unsigned char *pbPubkeyX,unsigned char *pbPubkeyY, void * pvENVELOPEDKEYBLOB_IPK, void * pvENVELOPEDKEYBLOB_EPK);

	/*
	��������:	����SM2������Կ�����ŷ�
	��������:	PCI_GenExportSM2EnvelopedKey
	�������:	hSessionHandle			�Ự���
				pbPubkeyX				�ⲿǩ����ԿX�����ȱ���Ϊ32��
				pbPubkeyY				�ⲿǩ����ԿY�����ȱ���Ϊ32��
	�������:	pvENVELOPEDKEYBLOB_IPK	�ڲ���Կ���ܵ�ECC��Կ�������ŷ�(����ΪOPST_SKF_ENVELOPEDKEYBLOB)
				pvENVELOPEDKEYBLOB_EPK	�ⲿ��Կ���ܵ�ECC��Կ�������ŷ�(����ΪOPST_SKF_ENVELOPEDKEYBLOB)
	����ֵ:   
	ʧ�ܣ�
	��������:	����SM2������Կ�����ŷ�
	*/
	COMMON_API unsigned int PCI_RestoreExportSM2EnvelopedKey(HANDLE hSessionHandle, unsigned char *pbPubkeyX,unsigned char *pbPubkeyY, 
		void * pvENVELOPEDKEYBLOB_IPK, void * pvENVELOPEDKEYBLOB_EPK);

	/*
	��������:	��PCI�豸
	��������:	PCI_Open
	�������:	
	�������:	phSessionHandle			PCI���
				phPCIHandle				�Ự���
	����ֵ:   
	ʧ�ܣ�
	��������:	��PCI�豸
	*/
	COMMON_API unsigned int PCI_Open(HANDLE *phPCIHandle, HANDLE *phSessionHandle);

	/*
	��������:	�ر�PCI�豸
	��������:	PCI_Close
	�������:	hSessionHandle      �Ự���
				hPCIHandle			PCI���
	�������:
	����ֵ:   
	ʧ�ܣ�
	��������:	�ر�PCI�豸
	*/
	COMMON_API unsigned int PCI_Close(HANDLE hPCIHandle, HANDLE hSessionHandle);

	/*
	��������:	IC����¼
	��������:	PCI_ICLogin
	�������:	hSessionHandle         �Ự���
				pbPINValue		����
				uiPINLen			�����
	�������:	
				puiUserID			�û�ID
				puiTrials		���������ʣ�����
	����ֵ:   
	ʧ�ܣ�
	��������:	IC����¼
	*/
	COMMON_API unsigned int PCI_ICLogin(HANDLE hSessionHandle,
		const unsigned char* pbPINValue, unsigned int uiPINLen , 
		unsigned int *puiUserID, unsigned int *puiTrials);

	/*
	��������:	IC���ǳ�
	��������:	PCI_ICLogout
	�������:	hSessionHandle         �Ự���
				uiUserID			�û�ID
	�������:	
	����ֵ:   
	ʧ�ܣ�
	��������:	IC���ǳ�
	*/
	COMMON_API unsigned int PCI_ICLogout(HANDLE hSessionHandle, unsigned int uiUserID);

	/*
	��������:	������Կ����
	��������:	PCI_CheckExistRootSM2Keys
	�������:	hSessionHandle         �Ự���
	�������:
	����ֵ:   
	ʧ�ܣ�
	��������:	������Կ����
	*/
	COMMON_API unsigned int PCI_CheckExistRootSM2Keys(HANDLE hSessionHandle);

	/*
	��������:	������Կ������
	��������:	PCI_CheckExistRootSM2Keys
	�������:	hSessionHandle         �Ự���
	�������:
	����ֵ:   
	ʧ�ܣ�
	��������:	������Կ������
	*/
	COMMON_API unsigned int PCI_CheckNotExistRootSM2Keys(HANDLE hSessionHandle);

	/*
	��������:	���ɸ���Կ
	��������:	PCI_GenRootSM2Keys
	�������:	hSessionHandle         �Ự���
	�������:
	����ֵ:   
	ʧ�ܣ�
	��������:	���ɸ���Կ
	*/
	COMMON_API unsigned int PCI_GenRootSM2Keys(HANDLE hSessionHandle,unsigned char *pbCipherValue, unsigned int *puiCipherLen);

	/*
	��������:	������Կ
	��������:	PCI_ExportRootSM2Keys
	�������:	hSessionHandle         �Ự���
	�������:	pbPubKeyX		��ԿXֵ
				puiPubKeyLenX		��ԿX����
				pbPubKeyY		��ԿYֵ
				puiPubKeyLenY		��ԿY����
	����ֵ:   
	ʧ�ܣ�
	��������:	������Կ
	*/
	COMMON_API unsigned int PCI_ExportRootSM2Keys(HANDLE hSessionHandle, unsigned char *pbPubKeyX, unsigned int *puiPubKeyLenX,
		unsigned char *pbPubKeyY, unsigned int *puiPubKeyLenY);

	/*
	��������:	������Կ
	��������:	PCI_GenSM2Keys
	�������:	hSessionHandle         �Ự���
	�������:
	����ֵ:   
	ʧ�ܣ�
	��������:	������Կ
	*/
	COMMON_API unsigned int PCI_GenSM2Keys(HANDLE hSessionHandle,unsigned char *pbCipherValue, unsigned int *puiCipherLen);


	/*
	��������:	����Կǩ��
	��������:	PCI_SignWithRootSM2Keys
	�������:	hSessionHandle         �Ự���
				pbPW		˽Կ��������
				uiPWLen			˽Կ�������볤��
				pbInValue		ǩ��ԭ��
				uiInLen			ǩ��ԭ�ĳ���
	�������:
				pbSigValue		ǩ��ֵ��
				puiSigLen		ǩ��ֵ�ĳ���
	����ֵ:   
	ʧ�ܣ�
	��������:	����Կǩ��
	*/
	COMMON_API unsigned int PCI_SignWithRootSM2Keys(HANDLE hSessionHandle, 
		const unsigned char * pbPW, unsigned int uiPWLen,
		const unsigned char *pbInValue, unsigned int uiInLen,unsigned int uiAlg,
		unsigned char * pbSigValue, unsigned int * puiSigLen
		);

	/*
	��������:	�ⲿ˽Կǩ��
	��������:	PCI_SignWithSM2Keys
	�������:	hSessionHandle         �Ự���
				pbPrivateKey	˽Կ
				uiPrivateKeyLen		˽Կ����
				pbInValue		ǩ��ԭ��
				uiInLen			ǩ��ԭ�ĳ���
	�������:	
				pbSigValue		ǩ��ֵ��
				puiSigLen		ǩ��ֵ�ĳ���
	����ֵ:   
	ʧ�ܣ�
	��������:	�ⲿ˽Կǩ��
	*/
	COMMON_API unsigned int PCI_SignWithSM2Keys(HANDLE hSessionHandle,
		const unsigned char * pbPrivateKey, unsigned int uiPrivateKeyLen,
		const unsigned char * pbInValue, unsigned int uiInLen,
		unsigned char * pbSigValue, unsigned int * puiSigLen
		);

	/*
	��������:	�ⲿ��Կ��֤ǩ��
	��������:	PCI_VerifyWithSM2Keys
	�������:	hSessionHandle         �Ự���
				pbPubkeyX		��ԿX
				uiPubkeyXLen		��ԿX����
				pbPubkeyY		��ԿY
				uiPubkeyYLen		��ԿY����
				pbInValue		ǩ��ԭ��
				uiInLen			ǩ��ԭ�ĳ���
				pbSigValue		ǩ��ֵ��
				uiSigLen		ǩ��ֵ�ĳ���
	�������:	
	����ֵ:   
	ʧ�ܣ�
	��������:	�ⲿ��Կ��֤ǩ��
	*/
	COMMON_API unsigned int PCI_VerifyWithSM2Keys(HANDLE hSessionHandle,
		const unsigned char * pbPubkeyX, unsigned int uiPubkeyXLen,
		const unsigned char * pbPubkeyY, unsigned int uiPubkeyYLen,
		const unsigned char * pbInValue, unsigned int uiInLen,
		const unsigned char * pbSigValue, unsigned int uiSigLen
		);

	/*
	��������:	���ݳ�ʼ��
	��������:	PCI_BackupInit
	�������:	hSessionHandle         �Ự���
	�������:	
	����ֵ:   
	ʧ�ܣ�
	��������:	���ݳ�ʼ��
	*/
	COMMON_API unsigned int PCI_BackupInit(HANDLE hSessionHandle);

	/*
	��������:	���ݷ���
	��������:	PCI_BackupAuthor
	�������:	hSessionHandle         �Ự���
				pbPinValue		����
				uiPinLen			�����
	�������:	
	����ֵ:   
	ʧ�ܣ�
	��������:	������Ȩ
	*/
	COMMON_API unsigned int PCI_BackupKeyComponent(HANDLE hSessionHandle, unsigned int uiNumber, 
		const unsigned char *pbPinValue, unsigned int uiPinLen, unsigned int *puiTrials);

	/*
	��������:	����
	��������:	PCI_BackupECC
	�������:	hSessionHandle         �Ự���
	�������:	
				pbCipherValue	����ECC��Կ����
				uiCipherLen		����ECC��Կ����
	����ֵ:   
	ʧ�ܣ�
	��������:	����
	*/
	COMMON_API unsigned int PCI_BackupECC(HANDLE hSessionHandle, unsigned int bFlagSign,
		unsigned char *pbCipherValue, unsigned int *puiCipherLen);
	
	/*
	��������:	���ݽ���
	��������:	PCI_BackupFinal
	�������:	hSessionHandle         �Ự���
	�������:	
	����ֵ:   
	ʧ�ܣ�
	��������:	���ݽ���
	*/
	COMMON_API unsigned int PCI_BackupFinal(HANDLE hSessionHandle);

	/*
	��������:	�ָ���ʼ��
	��������:	PCI_RestoreInit
	�������:	hSessionHandle         �Ự���
	�������:	
	����ֵ:   
	ʧ�ܣ�
	��������:	�ָ���ʼ��
	*/
	COMMON_API unsigned int PCI_RestoreInit(HANDLE hSessionHandle);

	/*
	��������:	�ָ�����
	��������:	PCI_RestoreAuthor
	�������:	hSessionHandle         �Ự���
				pbPinValue		����
				uiPinLen			�����
	�������:	
	����ֵ:   
	ʧ�ܣ�
	��������:	�ָ�����
	*/
	COMMON_API unsigned int PCI_RestoreKeyComponent(HANDLE hSessionHandle, 
		const unsigned char *pbPinValue, unsigned int uiPinLen, unsigned int * puiTrials);
	
	/*
	��������:	�ָ�
	��������:	PCI_RestoreECC
	�������:	hSessionHandle         �Ự���
				pbCipherValue	����ECC��Կ����
				uiCipherLen		����ECC��Կ����
	�������:	
	����ֵ:   
	ʧ�ܣ�
	��������:	�ָ�
	*/
	COMMON_API unsigned int PCI_RestoreECC(HANDLE hSessionHandle, unsigned int bFlagSign,
		const unsigned char *pbCipherValue, unsigned int uiCipherLen);

	/*
	��������:	�ָ�����
	��������:	PCI_RestoreFinal
	�������:	hSessionHandle         �Ự���
	�������:	
	����ֵ:   
	ʧ�ܣ�
	��������:	�ָ�����
	*/
	COMMON_API unsigned int PCI_RestoreFinal(HANDLE hSessionHandle);


#ifdef __cplusplus
}
#endif

#endif /* PCI_FUNC_DEF_H_ */