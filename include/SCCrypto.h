/******************************************************************************
******************************************************************************/

#include <windows.h>

// ���֧�ָ���
#define SCCRYPT_TF_MAX_DEV_NUM             26
// ������󳤶�
#define SCCRYPT_TF_MAX_DEV_NAME_LEN        33


// Ψһ���кŵĳ���
#define SCCRYPT_SN_LEN                     8


#ifdef __cplusplus
extern "C" {
#endif



// ö��TF�豸
// ������
//   pszDrives������TF�豸�����ַ��������ΪNULL��pulDrivesLen����������buffer�Ĵ�С
//   pulDrivesLen������ָ��buffer pszDrives�Ĵ�С
//   pulDriveNum������UKey�豸����
// ����ֵ��
//   ����ִ�гɹ���������0�����򷵻���Ӧ�Ĵ�����
// ����ֵ��
//   �ɹ�����0�����򷵻���Ӧ�Ĵ�����
DWORD __stdcall SC_ListDevs
(
	OUT char *pszDrives,
	IN OUT DWORD *pulDrivesLen,
	OUT DWORD *pulDriveNum
);


// �����豸
// ����
//   pszDrive����SC_ListDevsö�ٵ���UKey�豸
//   phDevice�������豸������
// ����ֵ��
//   ����ִ�гɹ���������0�����򷵻���Ӧ�Ĵ�����
DWORD __stdcall SC_ConnectDev
(
	IN char *pszDrive,
	OUT HANDLE *phDevice
);


// �Ͽ��豸������
// ������
//   hDevice����SC_ConnectDev���ص��豸������
// ����ֵ��
//   �ɹ�����0�����򷵻���Ӧ�Ĵ�����
DWORD __stdcall SC_DisconnectDev
(
	IN HANDLE hDevice
);


// ��ȡTF��Ψһ���к�
// ������
//   hDevice����SC_ConnectDev���ص��豸������
//   pbSN���������кţ���һ���ֽ�Ϊ��ԿIndex
//   pulSNLen���������кŵĳ��ȣ����кų���ΪTFCRYPT_SN_LEN
// ����ֵ��
//   �ɹ�����0�����򷵻���Ӧ�Ĵ�����
DWORD __stdcall SC_GetSCSN
(
	IN HANDLE hDevice,
	OUT BYTE *pbSN,
	IN OUT DWORD *pulSNLen
);



// ��֤PIN���ݶ����ĵķ�ʽ��֤
// ������
//   hDevice����SC_ConnectDev���ص��豸������
//   pbPIN��PIN��
//   ulPINLen��PIN�볤��
//   pulTrials�����PIN���������, �򷵻ػ��������ԵĴ���
// ����ֵ��
//   �ɹ�����0�����򷵻���Ӧ�Ĵ�����
DWORD __stdcall SC_VerifyPIN
(
	IN HANDLE hDevice,
	IN BYTE *pbPIN,
	IN DWORD ulPINLen,
	OUT DWORD *pulTrials
);


/*
// ����SM2��Կ�ԣ���������Կ
// ������
//   hDevice����SC_ConnectDev���ص��豸������
//   pbPubKey�������Կ����
//   pulPubKeyLen�������Կ���ݳ���
// ����ֵ��
//   �ɹ�����0�����򷵻���Ӧ�Ĵ�����
DWORD __stdcall SC_GenSM2KeyPair
(
	IN HANDLE hDevice,
	IN BYTE *pbPubKey,
	IN OUT DWORD *pulPubKeyLen
);
*/

// ����SM2��Կ
// ������
//   hDevice����SC_ConnectDev���ص��豸������
//   pbPubKey�������Կ����
//   pulPubKeyLen�������Կ���ݳ���
// ����ֵ��
//   �ɹ�����0�����򷵻���Ӧ�Ĵ�����
DWORD __stdcall SC_ExportSM2PubKey
(
	IN HANDLE hDevice,
	IN BYTE *pbPubKey,
	IN OUT DWORD *pulPubKeyLen
);




// ��װSM9��Կ��
//   hDevice����SC_ConnectDev���ص��豸������
//   ulIndex���û���Կ��Index
//   pbUserID���û�ID
//   ulUserIDLen���û�ID����
//   pbPubKeySign��ǩ����Կ�����ģ�
//   ulPubKeySignLen��ǩ����Կ����
//   pbPriKeySign������ǩ��˽Կ��SM2��Կ���ܣ�
//   ulPriKeySignLen������ǩ��˽Կ����
//   pbPubKeyExc��������Կ�����ģ�
//   ulPubKeyExcLen��������Կ����
//   pbPriKeyExc�����Ľ���˽Կ��SM2��Կ���ܣ�
//   ulPriKeyExcLen�����Ľ���˽Կ����
DWORD __stdcall SC_InstallSM9KeyPair
(
	IN HANDLE hDevice,

	IN DWORD ulIndex,
	IN BYTE *pbUserID,
	IN DWORD ulUserIDLen,

	IN BYTE *pbPubKeySign,
	IN DWORD ulPubKeySignLen,
	IN BYTE *pbPriKeySign,
	IN DWORD ulPriKeySignLen,

	IN BYTE *pbPubKeyExc,
	IN DWORD ulPubKeyExcLen,
	IN BYTE *pbPriKeyExc,
	IN DWORD ulPriKeyExcLen
);


// ��ȡ�û����ID
// ��ȡ֤������
// ������
//   hDevice����SC_ConnectDev���ص��豸������
//   ulIndex������ȡ��֤�������ţ���0��ʼ
//   pbID�������û����ID
//   pulIDLen�������û���ݳ���
// ����ֵ��
//   �ɹ�����0�����򷵻���Ӧ�Ĵ�����
DWORD __stdcall SC_GetUserID
(
	IN HANDLE hDevice, 
	IN DWORD ulIndex,
	OUT BYTE *pbID,
	IN OUT DWORD *pulIDLen
);



// ǩ��
//   hDevice����SC_ConnectDev���ص��豸������
//   ulIndex: ��Կ��Index
//   pbInData����ǩ������
//   ulInDataLen����ǩ�����ݳ���
//   pbSignature�����ǩ��ֵ
//   pulSignLen�����ǩ��ֵ�ĳ���
DWORD __stdcall SC_SM9Sign
(
	IN HANDLE hDevice,
	IN DWORD ulIndex,
	IN BYTE *pbInData,
	IN DWORD ulInDataLen,
	OUT BYTE *pbSignature,
	IN OUT DWORD *pulSignLen
);



// ��ǩ
//   hDevice����SC_ConnectDev���ص��豸������
//   ulIndex: ��Կ��Index
//   pbUserID��ǩ�����û�ID
//   ulUserIDLen��ǩ�����û�ID����
//   pbInData������֤ǩ��������
//   ulInDataLen�����ݳ���
//   pbSignature������֤��ǩ��ֵ
//   pulSignLen������֤��ǩ��ֵ����
DWORD __stdcall SC_SM9Verify
(
	IN HANDLE hDevice,
	IN DWORD ulIndex,
	IN BYTE *pbUserID,
	IN DWORD ulUserIDLen,
	IN BYTE *pbInData,
	IN DWORD ulInDataLen,
	IN BYTE *pbSignature,
	IN DWORD ulSignLen
);




// ����SessionKey�öԷ���Կ���ܵ���
//   hDevice����SC_ConnectDev���ص��豸������
//   ulIndex: ��Կ��Index
//   pbUserID���û�ID
//   ulUserIDLen���û�ID����
//   pbCipherSK�����SessionKey����
//   pulCipherSKLen�����SessionKey���ĳ���
DWORD __stdcall SC_ExportSessionKey
(
	IN HANDLE hDevice,
	
	IN DWORD ulIndex,

	IN BYTE *pbUserID,
	IN DWORD ulUserIDLen,

	OUT BYTE *pbCipherSK,
	IN OUT DWORD *pulCipherSKLen
);


// ����SessionKey
//   hDevice����SC_ConnectDev���ص��豸������
//   ulIndex: ��Կ��Index
//   pbUserID���û�ID
//   ulUserIDLen���û�ID����
//   pbCipherSK��SessionKey����
//   ulCipherSKLen��SessionKey���ĳ���
DWORD __stdcall SC_ImportSessionKey
(
	IN HANDLE hDevice,
	IN DWORD ulIndex,
	IN BYTE *pbUserID,
	IN DWORD ulUserIDLen,
	OUT BYTE *pbCipherSK,
	IN DWORD ulCipherSKLen
);


// �㷨��ʼ��
//   hDevice����SC_ConnectDev���ص��豸������
DWORD __stdcall SC_CryptInit
(
	IN HANDLE hDevice
);


// ��������
//   hDevice����SC_ConnectDev���ص��豸������
//   pbCount�����ܼ���
//   ulCountLen�����ܼ�������
//   pbPlaintext����������
//   ulPlaintextLen���������ݳ���
//   pbCiphertext����������
//   pulPlaintextLen�������������ݳ���
DWORD __stdcall SC_EncryptUpdate
(
	IN HANDLE hDevice,
	IN BYTE *pbCount,
	IN DWORD ulCountLen,
	IN BYTE *pbPlaintext,
	IN DWORD ulPlaintextLen,
	OUT BYTE *pbCiphertext,
	IN OUT DWORD *pulCiphertextLen
);


// ��������
//   hDevice����SC_ConnectDev���ص��豸������
//   pbCount�����ܼ���
//   ulCountLen�����ܼ�������
//   pbCiphertext����������
//   ulPlaintextLen���������ݳ���
//   pbPlaintext��������������
//   pulPlaintextLen�������������ݳ���
DWORD __stdcall SC_DecryptUpdate
(
	IN HANDLE hDevice,
	IN BYTE *pbCount,
	IN DWORD ulCountLen,
	IN BYTE *pbCiphertext,
	IN DWORD ulCiphertextLen,
	OUT BYTE *pbPlaintext,
	IN OUT DWORD *pulPlaintextLen
);


// �㷨����
//   hDevice����SC_ConnectDev���ص��豸������
DWORD __stdcall SC_CryptFinal
(
	IN HANDLE hDevice
);


#ifdef __cplusplus
}
#endif

