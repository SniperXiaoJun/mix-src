


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
	COMMON_API unsigned long PCI_GenExportSM2EnvelopedKey(HANDLE hSessionHandle, unsigned char *pbPubkeyX,unsigned char *pbPubkeyY, void * pvENVELOPEDKEYBLOB_IPK, void * pvENVELOPEDKEYBLOB_EPK);

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
	COMMON_API unsigned long PCI_RestoreExportSM2EnvelopedKey(HANDLE hSessionHandle, unsigned char *pbPubkeyX,unsigned char *pbPubkeyY, 
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
	COMMON_API unsigned long PCI_Open(HANDLE *phPCIHandle, HANDLE *phSessionHandle);

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
	COMMON_API unsigned long PCI_Close(HANDLE hPCIHandle, HANDLE hSessionHandle);

	/*
	��������:	IC����¼
	��������:	PCI_ICLogin
	�������:	hSessionHandle         �Ự���
				pbPINValue		����
				ulPINLen			�����
	�������:	
				pulUserID			�û�ID
				pulTrials		���������ʣ�����
	����ֵ:   
	ʧ�ܣ�
	��������:	IC����¼
	*/
	COMMON_API unsigned long PCI_ICLogin(HANDLE hSessionHandle,
		const unsigned char* pbPINValue, unsigned long ulPINLen , 
		unsigned long *pulUserID, unsigned long *pulTrials);

	/*
	��������:	IC���ǳ�
	��������:	PCI_ICLogout
	�������:	hSessionHandle         �Ự���
				ulUserID			�û�ID
	�������:	
	����ֵ:   
	ʧ�ܣ�
	��������:	IC���ǳ�
	*/
	COMMON_API unsigned long PCI_ICLogout(HANDLE hSessionHandle, unsigned long ulUserID);

	/*
	��������:	������Կ����
	��������:	PCI_CheckExistRootSM2Keys
	�������:	hSessionHandle         �Ự���
	�������:
	����ֵ:   
	ʧ�ܣ�
	��������:	������Կ����
	*/
	COMMON_API unsigned long PCI_CheckExistRootSM2Keys(HANDLE hSessionHandle);

	/*
	��������:	������Կ������
	��������:	PCI_CheckExistRootSM2Keys
	�������:	hSessionHandle         �Ự���
	�������:
	����ֵ:   
	ʧ�ܣ�
	��������:	������Կ������
	*/
	COMMON_API unsigned long PCI_CheckNotExistRootSM2Keys(HANDLE hSessionHandle);

	/*
	��������:	���ɸ���Կ
	��������:	PCI_GenRootSM2Keys
	�������:	hSessionHandle         �Ự���
	�������:
	����ֵ:   
	ʧ�ܣ�
	��������:	���ɸ���Կ
	*/
	COMMON_API unsigned long PCI_GenRootSM2Keys(HANDLE hSessionHandle,unsigned char *pbCipherValue, unsigned long *pulCipherLen);

	/*
	��������:	������Կ
	��������:	PCI_ExportRootSM2Keys
	�������:	hSessionHandle         �Ự���
	�������:	pbPubKeyX		��ԿXֵ
				pulPubKeyLenX		��ԿX����
				pbPubKeyY		��ԿYֵ
				pulPubKeyLenY		��ԿY����
	����ֵ:   
	ʧ�ܣ�
	��������:	������Կ
	*/
	COMMON_API unsigned long PCI_ExportRootSM2Keys(HANDLE hSessionHandle, unsigned char *pbPubKeyX, unsigned long *pulPubKeyLenX,
		unsigned char *pbPubKeyY, unsigned long *pulPubKeyLenY);

	/*
	��������:	������Կ
	��������:	PCI_GenSM2Keys
	�������:	hSessionHandle         �Ự���
	�������:
	����ֵ:   
	ʧ�ܣ�
	��������:	������Կ
	*/
	COMMON_API unsigned long PCI_GenSM2Keys(HANDLE hSessionHandle,unsigned char *pbCipherValue, unsigned long *pulCipherLen);


	/*
	��������:	����Կǩ��
	��������:	PCI_SignWithRootSM2Keys
	�������:	hSessionHandle         �Ự���
				pbPW		˽Կ��������
				ulPWLen			˽Կ�������볤��
				pbInValue		ǩ��ԭ��
				ulInLen			ǩ��ԭ�ĳ���
	�������:
				pbSigValue		ǩ��ֵ��
				pulSigLen		ǩ��ֵ�ĳ���
	����ֵ:   
	ʧ�ܣ�
	��������:	����Կǩ��
	*/
	COMMON_API unsigned long PCI_SignWithRootSM2Keys(HANDLE hSessionHandle, 
		const unsigned char * pbPW, unsigned long ulPWLen,
		const unsigned char *pbInValue, unsigned long ulInLen,unsigned long ulAlg,
		unsigned char * pbSigValue, unsigned long * pulSigLen
		);

	/*
	��������:	�ⲿ˽Կǩ��
	��������:	PCI_SignWithSM2Keys
	�������:	hSessionHandle         �Ự���
				pbPrivateKey	˽Կ
				ulPrivateKeyLen		˽Կ����
				pbInValue		ǩ��ԭ��
				ulInLen			ǩ��ԭ�ĳ���
	�������:	
				pbSigValue		ǩ��ֵ��
				pulSigLen		ǩ��ֵ�ĳ���
	����ֵ:   
	ʧ�ܣ�
	��������:	�ⲿ˽Կǩ��
	*/
	COMMON_API unsigned long PCI_SignWithSM2Keys(HANDLE hSessionHandle,
		const unsigned char * pbPrivateKey, unsigned long ulPrivateKeyLen,
		const unsigned char * pbInValue, unsigned long ulInLen,
		unsigned char * pbSigValue, unsigned long * pulSigLen
		);

	/*
	��������:	�ⲿ��Կ��֤ǩ��
	��������:	PCI_VerifyWithSM2Keys
	�������:	hSessionHandle         �Ự���
				pbPubkeyX		��ԿX
				ulPubkeyXLen		��ԿX����
				pbPubkeyY		��ԿY
				ulPubkeyYLen		��ԿY����
				pbInValue		ǩ��ԭ��
				ulInLen			ǩ��ԭ�ĳ���
				pbSigValue		ǩ��ֵ��
				ulSigLen		ǩ��ֵ�ĳ���
	�������:	
	����ֵ:   
	ʧ�ܣ�
	��������:	�ⲿ��Կ��֤ǩ��
	*/
	COMMON_API unsigned long PCI_VerifyWithSM2Keys(HANDLE hSessionHandle,
		const unsigned char * pbPubkeyX, unsigned long ulPubkeyXLen,
		const unsigned char * pbPubkeyY, unsigned long ulPubkeyYLen,
		const unsigned char * pbInValue, unsigned long ulInLen,
		const unsigned char * pbSigValue, unsigned long ulSigLen
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
	COMMON_API unsigned long PCI_BackupInit(HANDLE hSessionHandle);

	/*
	��������:	���ݷ���
	��������:	PCI_BackupAuthor
	�������:	hSessionHandle         �Ự���
				pbPinValue		����
				ulPinLen			�����
	�������:	
	����ֵ:   
	ʧ�ܣ�
	��������:	������Ȩ
	*/
	COMMON_API unsigned long PCI_BackupKeyComponent(HANDLE hSessionHandle, unsigned long ulNumber, 
		const unsigned char *pbPinValue, unsigned long ulPinLen, unsigned long *pulTrials);

	/*
	��������:	����
	��������:	PCI_BackupECC
	�������:	hSessionHandle         �Ự���
	�������:	
				pbCipherValue	����ECC��Կ����
				ulCipherLen		����ECC��Կ����
	����ֵ:   
	ʧ�ܣ�
	��������:	����
	*/
	COMMON_API unsigned long PCI_BackupECC(HANDLE hSessionHandle, unsigned long bFlagSign,
		unsigned char *pbCipherValue, unsigned long *pulCipherLen);
	
	/*
	��������:	���ݽ���
	��������:	PCI_BackupFinal
	�������:	hSessionHandle         �Ự���
	�������:	
	����ֵ:   
	ʧ�ܣ�
	��������:	���ݽ���
	*/
	COMMON_API unsigned long PCI_BackupFinal(HANDLE hSessionHandle);

	/*
	��������:	�ָ���ʼ��
	��������:	PCI_RestoreInit
	�������:	hSessionHandle         �Ự���
	�������:	
	����ֵ:   
	ʧ�ܣ�
	��������:	�ָ���ʼ��
	*/
	COMMON_API unsigned long PCI_RestoreInit(HANDLE hSessionHandle);

	/*
	��������:	�ָ�����
	��������:	PCI_RestoreAuthor
	�������:	hSessionHandle         �Ự���
				pbPinValue		����
				ulPinLen			�����
	�������:	
	����ֵ:   
	ʧ�ܣ�
	��������:	�ָ�����
	*/
	COMMON_API unsigned long PCI_RestoreKeyComponent(HANDLE hSessionHandle, 
		const unsigned char *pbPinValue, unsigned long ulPinLen, unsigned long * pulTrials);
	
	/*
	��������:	�ָ�
	��������:	PCI_RestoreECC
	�������:	hSessionHandle         �Ự���
				pbCipherValue	����ECC��Կ����
				ulCipherLen		����ECC��Կ����
	�������:	
	����ֵ:   
	ʧ�ܣ�
	��������:	�ָ�
	*/
	COMMON_API unsigned long PCI_RestoreECC(HANDLE hSessionHandle, unsigned long bFlagSign,
		const unsigned char *pbCipherValue, unsigned long ulCipherLen);

	/*
	��������:	�ָ�����
	��������:	PCI_RestoreFinal
	�������:	hSessionHandle         �Ự���
	�������:	
	����ֵ:   
	ʧ�ܣ�
	��������:	�ָ�����
	*/
	COMMON_API unsigned long PCI_RestoreFinal(HANDLE hSessionHandle);


#ifdef __cplusplus
}
#endif

#endif /* PCI_FUNC_DEF_H_ */