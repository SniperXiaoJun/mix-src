#ifndef __SKFINTERFACE_H
#define __SKFINTERFACE_H

//6.1	�㷨��ʶ
//6.1.1	���������㷨��ʶ
//���������㷨��ʶ���������㷨�����ͺͼ���ģʽ��
//���������㷨��ʶ�ı������Ϊ���ӵ�λ����λ����0λ����7λ��λ��ʾ���������㷨����ģʽ��
//��8λ����31λ��λ��ʾ���������㷨���ͣ����������㷨�ı�ʶ������ʾ��
#define	SGD_SM1_ECB		0x00000101		//SM1�㷨ECB����ģʽ
#define	SGD_SM1_CBC		0x00000102		//SM1�㷨CBC����ģʽ
#define	SGD_SM1_CFB		0x00000104		//SM1�㷨CFB����ģʽ
#define	SGD_SM1_OFB		0x00000108		//SM1�㷨OFB����ģʽ
#define	SGD_SM1_MAC		0x00000110		//SM1�㷨MAC����
#define	SGD_SSF33_ECB	0x00000201		//SSF33�㷨ECB����ģʽ
#define	SGD_SSF33_CBC	0x00000202		//SSF33�㷨CBC����ģʽ
#define	SGD_SSF33_CFB	0x00000204		//SSF33�㷨CFB����ģʽ
#define	SGD_SSF33_OFB	0x00000208		//SSF33�㷨OFB����ģʽ
#define	SGD_SSF33_MAC	0x00000210		//SSF33�㷨MAC����
#define	SGD_SMS4_ECB	0x00000401		//SMS4�㷨ECB����ģʽ
#define	SGD_SMS4_CBC	0x00000402		//SMS4�㷨CBC����ģʽ
#define	SGD_SMS4_CFB	0x00000404		//SMS4�㷨CFB����ģʽ
#define	SGD_SMS4_OFB	0x00000408		//SMS4�㷨OFB����ģʽ
#define	SGD_SMS4_MAC	0x00000410		//SMS4�㷨MAC����

#define SGD_3DES_ECB	0x00000001  //3DES�㷨ECB����ģʽ

#define	SGD_ZYJM_ECB	0x00000601		//ZYJM�㷨ECBģʽ
#define	SGD_ZYJM_CBC	0x00000602		//ZYJM�㷨CBCģʽ

//6.1.2	�ǶԳ������㷨��ʶ
//�ǶԳ������㷨��ʶ�������������㷨�����ͣ���ʹ�÷ǶԳ��㷨��������ǩ������ʱ���ɽ��ǶԳ������㷨��ʶ���������Ӵ��㷨
//��ʶ������"��"�����ʹ�ã���"RSA with SHA1"�ɱ�ʾΪSGD_RSA | SGD_SHA1����0x00010002��"|"��ʾ"��"���㡣
//�ǶԳ������㷨��ʶ�ı������Ϊ���ӵ�λ����λ����0λ����7λΪ0����8λ����15λ��λ��ʾ�ǶԳ������㷨���㷨Э�飬�����
//��ʾ�ķǶԳ��㷨û����Ӧ���㷨Э����Ϊ0����16λ����31λ��λ��ʾ�ǶԳ������㷨���ͣ��ǶԳ������㷨�ı�ʶ������ʾ��
#define	SGD_RSA			0x00010000		//RSA�㷨
#define	SGD_SM2_1		0x00020100		//��Բ����ǩ���㷨
#define	SGD_SM2_2		0x00020200		//��Բ������Կ����Э��
#define	SGD_SM2_3		0x00020400		//��Բ���߼����㷨
#define	SGD_ECC_512		0x00040100		//ECC512�㷨

//6.1.3	�����Ӵ��㷨��ʶ
//�����Ӵ��㷨��ʶ�������ڽ��������Ӵ���������MACʱӦ�ã�Ҳ������ǶԳ������㷨��ʶ������"��"�����ʹ�ã���ʾǩ������
//ǰ�����ݽ��������Ӵ�������㷨���͡�
//�����Ӵ��㷨��ʶ�ı������Ϊ���ӵ�λ����λ����0λ����7λ��ʾ�����Ӵ��㷨����8λ����31λΪ0�������Ӵ��㷨�ı�ʶ������ʾ��
#define	SGD_SM3			0x00000001		//SM3�����Ӵ��㷨
#define	SGD_SHA1		0x00000002		//SHA1�����Ӵ��㷨
#define	SGD_SHA256		0x00000004		//SHA256�����Ӵ��㷨

//6.2	������������
//INT8	�з���8λ����	
//INT16	�з���16λ����	
//INT32	�з���32λ����	
//UINT8	�޷���8λ����	
//UINT16	�޷���16λ����	
//UINT32	�޷���32λ����	
//BOOL	�������ͣ�ȡֵΪTRUE��FALSE	
//BYTE	�ֽ����ͣ��޷���8λ����
typedef signed char         INT8, *PINT8;
typedef signed short        INT16, *PINT16;
typedef signed int          INT32, *PINT32;
typedef unsigned char       UINT8, *PUINT8;
typedef unsigned short      UINT16, *PUINT16;
typedef unsigned int        UINT32, *PUINT32;

typedef UINT8 BYTE;
//CHAR	�ַ����ͣ��޷���8λ����
typedef UINT8 CHAR1;
//SHORT	���������з���16λ
typedef INT16 SHORT;
//USHORT	�޷���16λ����	
typedef UINT16 USHORT;
//LONG 	���������з���32λ����	
typedef INT32 LONG1;
//ULONG	���������޷���32λ����
typedef UINT32 ULONG32;
//UINT	�޷���32λ����	
typedef UINT32 UINT;
//WORD	�����ͣ��޷���16λ����	
typedef UINT16 WORD;
//DWORD	˫�����ͣ��޷���32λ����
typedef UINT32 DWORD1;
//FLAGS	��־���ͣ��޷���32λ����	
typedef UINT32 FLAGS;
//LPSTR	8λ�ַ���ָ�룬����UTF8��ʽ�洢������	
typedef char * LPSTR;
//HANDLE 	�����ָ���������ݶ������ʼ��ַ	
typedef  void * HANDLE;
//DEVHANDLE	�豸���	
typedef HANDLE DEVHANDLE;
//HAPPLICATION	Ӧ�þ��	
typedef HANDLE HAPPLICATION;
//HCONTAINER	�������	
typedef HANDLE HCONTAINER;

//6.3	��������
#ifndef TRUE
#define	TRUE	0x00000001		//����ֵΪ��
#endif

#ifndef FALSE
#define	FALSE	0x00000000		//����ֵΪ��
#endif

#ifndef DEVAPI
#define	DEVAPI	__stdcall		//__stdcall�������÷�ʽ
#endif



#ifndef ADMIN_TYPE
#define	ADMIN_TYPE	0			//����ԱPIN����
#endif

#ifndef USER_TYPE
#define	USER_TYPE	1			//�û�PIN����
#endif

#pragma pack(push, 1)

//6.4	������������
//6.4.1	�汾
typedef struct Struct_Version{
	BYTE major;		//���汾��
	BYTE minor;		//�ΰ汾��	
}VERSION;
//���汾�źʹΰ汾����"."�ָ������� Version 1.0�����汾��Ϊ1���ΰ汾��Ϊ0��Version 2.10�����汾��Ϊ2���ΰ汾��Ϊ10��

//6.4.2	�豸��Ϣ
typedef struct Struct_DEVINFO{
	VERSION		Version;					//�汾��	���ݽṹ�汾�ţ����ṹ�İ汾��Ϊ1.0
	CHAR		Manufacturer[64];			//�豸������Ϣ	�� '\0'Ϊ��������ASCII�ַ���
	CHAR		Issuer[64];					//���г�����Ϣ	�� '\0'Ϊ��������ASCII�ַ���
	CHAR		Label[32];					//�豸��ǩ	�� '\0'Ϊ��������ASCII�ַ���
	CHAR		SerialNumber[32];			//���к�	�� '\0'Ϊ��������ASCII�ַ���
	VERSION		HWVersion;					//�豸Ӳ���汾
	VERSION		FirmwareVersion;			//�豸����̼��汾
	ULONG		AlgSymCap;					//���������㷨��ʶ
	ULONG		AlgAsymCap;					//�ǶԳ������㷨��ʶ
	ULONG		AlgHashCap;					//�����Ӵ��㷨��ʶ
	ULONG		DevAuthAlgId;				//�豸��֤ʹ�õķ��������㷨��ʶ
	ULONG		TotalSpace;					//�豸�ܿռ��С
	ULONG		FreeSpace;					//�û����ÿռ��С
	//ULONG		MaxECCBufferSize;			// �ܹ������ ECC �������ݴ�С
	//ULONG		MaxBufferSize;				//�ܹ�����ķ���������Ӵ���������ݴ�С
	BYTE  		Reserved[64];				//������չ
}DEVINFO,*PDEVINFO;

//6.4.3	RSA��Կ���ݽṹ
#define MAX_RSA_MODULUS_LEN 256			//�㷨ģ������󳤶�
#define MAX_RSA_EXPONENT_LEN 4			//�㷨ָ������󳤶�
typedef struct Struct_RSAPUBLICKEYBLOB{
	ULONG	AlgID;									//�㷨��ʶ��
	ULONG	BitLen;									//ģ����ʵ��λ����	������8�ı���
	BYTE	Modulus[MAX_RSA_MODULUS_LEN];			//ģ��n = p * q	ʵ�ʳ���ΪBitLen/8�ֽ�
	BYTE	PublicExponent[MAX_RSA_EXPONENT_LEN];	//������Կe	һ��Ϊ0x00010001
}RSAPUBLICKEYBLOB, *PRSAPUBLICKEYBLOB;

//6.4.4	RSA˽Կ���ݽṹ
typedef struct Struct_RSAPRIVATEKEYBLOB{
	ULONG	AlgID;									//�㷨��ʶ��
	ULONG	BitLen;									//ģ����ʵ��λ����	������8�ı���
	BYTE	Modulus[MAX_RSA_MODULUS_LEN];			//ģ��n = p * q	ʵ�ʳ���ΪBitLen/8�ֽ�
	BYTE	PublicExponent[MAX_RSA_EXPONENT_LEN];	//������Կe	һ��Ϊ00010001
	BYTE	PrivateExponent[MAX_RSA_MODULUS_LEN];	//˽����Կd	ʵ�ʳ���ΪBitLen/8�ֽ�
	BYTE	Prime1[MAX_RSA_MODULUS_LEN/2];			//����p	ʵ�ʳ���ΪBitLen/16�ֽ�
	BYTE	Prime2[MAX_RSA_MODULUS_LEN/2];			//����q	ʵ�ʳ���ΪBitLen/16�ֽ�
	BYTE	Prime1Exponent[MAX_RSA_MODULUS_LEN/2];	//d mod (p-1)��ֵ	ʵ�ʳ���ΪBitLen/16�ֽ�
	BYTE	Prime2Exponent[MAX_RSA_MODULUS_LEN/2];	//d mod (q -1)��ֵ	ʵ�ʳ���ΪBitLen/16�ֽ�
	BYTE	Coefficient[MAX_RSA_MODULUS_LEN/2];		//qģp�ĳ˷���Ԫ	ʵ�ʳ���ΪBitLen/16�ֽ�
}RSAPRIVATEKEYBLOB, *PRSAPRIVATEKEYBLOB;

//6.4.5	ECC��Կ���ݽṹ
#define ECC_MAX_XCOORDINATE_BITS_LEN 512	//ECC�㷨X�������󳤶�
#define ECC_MAX_YCOORDINATE_BITS_LEN 512	//ECC�㷨Y�������󳤶�
typedef struct Struct_ECCPUBLICKEYBLOB{
	ULONG	BitLen;											//ģ����ʵ��λ����	������8�ı���
	BYTE	XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8];	//�����ϵ��X����	�������ϵ�����
	BYTE	YCoordinate[ECC_MAX_YCOORDINATE_BITS_LEN/8];	//�����ϵ��Y����	�������ϵ�����
}ECCPUBLICKEYBLOB, *PECCPUBLICKEYBLOB;

//6.4.6	ECC˽Կ���ݽṹ
#define ECC_MAX_MODULUS_BITS_LEN 512 //ECC�㷨ģ������󳤶ȡ�
typedef struct Struct_ECCPRIVATEKEYBLOB{
	ULONG	BitLen;											//ģ����ʵ��λ����	������8�ı���
	BYTE	PrivateKey[ECC_MAX_MODULUS_BITS_LEN/8];			//˽����Կ	�������ϵ�����
}ECCPRIVATEKEYBLOB, *PECCPRIVATEKEYBLOB;

//6.4.7	ECC�������ݽṹ
typedef struct Struct_ECCCIPHERBLOB{
	BYTE  XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8];		//��y�����Բ�����ϵĵ㣨x��y��
	BYTE  YCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8];		//��x�����Բ�����ϵĵ㣨x��y��
	BYTE  HASH[32];											//���ĵ��Ӵ�ֵ
	ULONG	CipherLen;										//�������ݳ���
	BYTE  Cipher[1];										//��������	ʵ�ʳ���ΪCipherLen
} ECCCIPHERBLOB, *PECCCIPHERBLOB;

//6.4.8	ECCǩ�����ݽṹ
//ECC�㷨ģ������󳤶�
typedef struct Struct_ECCSIGNATUREBLOB{
	BYTE r[ECC_MAX_XCOORDINATE_BITS_LEN/8];			//ǩ�������r����
	BYTE s[ECC_MAX_XCOORDINATE_BITS_LEN/8];			//ǩ�������s����
} ECCSIGNATUREBLOB, *PECCSIGNATUREBLOB;

//6.4.9	�����������
#define MAX_IV_LEN 32
typedef struct Struct_BLOCKCIPHERPARAM{
	BYTE	IV[MAX_IV_LEN];							//��ʼ������MAX_IV_LENΪ��ʼ����������󳤶�
	ULONG	IVLen;									//��ʼ����ʵ�ʳ��ȣ����ֽڼ��㣩
	ULONG	PaddingType;							//��䷽ʽ��0��ʾ����䣬1��ʾ����PKCS#5��ʽ�������
	ULONG	FeedBitLen;								//����ֵ��λ���ȣ���λ���㣩	ֻ���OFB��CFBģʽ
} BLOCKCIPHERPARAM, *PBLOCKCIPHERPARAM;

//6.4.10	ECC������Կ�Ա����ṹ
typedef struct SKF_ENVELOPEDKEYBLOB{
	ULONG Version;							// ��ǰ�汾Ϊ 1
	ULONG ulSymmAlgID;						// �Գ��㷨��ʶ���޶�ECBģʽ
	ULONG ulBits;							// ������Կ�Ե���Կλ����
	BYTE cbEncryptedPriKey[64];				// �Գ��㷨���ܵļ���˽Կ,����˽Կ��ԭ��ΪECCPRIVATEKEYBLOB�ṹ�е�PrivateKey��	
	// ����Ч����Ϊԭ�ĵģ�ulBits + 7��/8
	ECCPUBLICKEYBLOB PubKey;				// ������Կ�ԵĹ�Կ
	ECCCIPHERBLOB ECCCipherBlob;			// �ñ�����Կ���ܵĶԳ���Կ���ġ�
}ENVELOPEDKEYBLOB, *PENVELOPEDKEYBLOB;

//6.4.11	�ļ�����
typedef struct Struct_FILEATTRIBUTE{
	CHAR	FileName[32];					//�ļ���	��'\0'������ASCII�ַ�������󳤶�Ϊ32
	ULONG	FileSize;						//�ļ���С	�����ļ�ʱ������ļ���С
	ULONG	ReadRights;						//��ȡȨ��	��ȡ�ļ���Ҫ��Ȩ��
	ULONG	WriteRights;					//д��Ȩ��	д���ļ���Ҫ��Ȩ��
} FILEATTRIBUTE, *PFILEATTRIBUTE;

#pragma pack(pop)


//6.4.12	Ȩ������
#define SECURE_NEVER_ACCOUNT	0x00000000	//������
#define SECURE_ADM_ACCOUNT		0x00000001	//����ԱȨ��
#define SECURE_USER_ACCOUNT		0x00000010	//�û�Ȩ��
#define SECURE_ANYONE_ACCOUNT	0x000000FF	//�κ���

//6.4.13	�豸״̬
#define DEV_ABSENT_STATE		0x00000000	//�豸������
#define DEV_PRESENT_STATE		0x00000001	//�豸����
#define DEV_UNKNOW_STATE		0x00000002	//�豸״̬δ֪

//�ӿ�
#ifdef __cplusplus
extern "C" {
#endif

	//7.1	�豸����
	//7.1.2	�ȴ��豸����¼�
	//����ԭ��	ULONG DEVAPI SKF_WaitForDevEvent(LPSTR szDevName,ULONG *pulDevNameLen, ULONG *pulEvent)
	//��������	�ú����ȴ��豸������߰γ��¼���szDevName���ط����¼����豸���ơ�
	//����		szDevName		[OUT] �����¼����豸���ơ�
	//			pulDevNameLen	[IN/OUT] ����/���������������ʱ��ʾ���������ȣ����ʱ��ʾ�豸���Ƶ���Ч����,���Ȱ����ַ�����������
	//			pulEvent		[OUT]�¼����͡�1��ʾ���룬2��ʾ�γ���
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_WaitForDevEvent(LPSTR szDevName,ULONG *pulDevNameLen, ULONG *pulEvent);

	//7.1.3	ȡ���ȴ��豸����¼�
	//����ԭ��	ULONG DEVAPI SKF_CancelWaitForDevEvent()
	//��������	�ú���ȡ���ȴ��豸������߰γ��¼���
	//����		
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	//��ע		ʹ����������ִ�е�SKF_WaitForDevEvent�����������ء�
	ULONG DEVAPI SKF_CancelWaitForDevEvent();

	//7.1.4	ö���豸
	//����ԭ��	ULONG DEVAPI SKF_EnumDev(BOOL bPresent, LPSTR szNameList, ULONG *pulSize)
	//��������	��õ�ǰϵͳ�е��豸�б�
	//����		bPresent	[IN] ΪTRUE��ʾȡ��ǰ�豸״̬Ϊ���ڵ��豸�б�ΪFALSE��ʾȡ��ǰ����֧�ֵ��豸�б�
	//			szNameList	[OUT] �豸�����б�����ò���ΪNULL������pulSize��������Ҫ���ڴ�ռ��С��ÿ���豸�������Ե���'\0'��������˫'\0'��ʾ�б�Ľ�����
	//			pulSize		[IN��OUT] ����ʱ��ʾ�豸�����б�Ļ��������ȣ����ʱ��ʾszNameList��ռ�õĿռ��С��
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_EnumDev(BOOL bPresent, LPSTR szNameList, ULONG *pulSize);

	//7.1.5	�����豸
	//����ԭ��	ULONG DEVAPI SKF_ConnectDev (LPSTR szName, DEVHANDLE *phDev)
	//��������	ͨ���豸���������豸�������豸�ľ����
	//����		szName	[IN] �豸���ơ�
	//			phDev	[OUT] �����豸���������
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_ConnectDev(LPSTR szName, DEVHANDLE *phDev);

	//7.1.6	�Ͽ�����
	//����ԭ��	ULONG DEVAPI SKF_DisConnectDev (DEVHANDLE hDev)
	//��������	�Ͽ�һ���Ѿ����ӵ��豸�����ͷž����
	//����		hDev	[IN] �����豸ʱ���ص��豸�����
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	//��ע		������豸�ѱ�����������Ӧ���Ƚ������豸���Ͽ����Ӳ�������Ӱ���豸��Ȩ��״̬��
	ULONG DEVAPI SKF_DisConnectDev(DEVHANDLE hDev);

	//7.1.7	��ȡ�豸״̬
	//����ԭ��	ULONG DEVAPI SKF_GetDevState(LPSTR szDevName, ULONG *pulDevState)
	//��������	��ȡ�豸�Ƿ���ڵ�״̬��
	//����		szDevName	[IN] �豸���ơ�
	//			pulDevState	[OUT] �����豸״̬��
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_GetDevState(LPSTR szDevName, ULONG *pulDevState);

	//7.1.8	�����豸��ǩ
	//����ԭ��	ULONG DEVAPI SKF_SetLabel (DEVHANDLE hDev, LPSTR szLabel)
	//��������	�����豸��ǩ��
	//����		hDev	[IN] �����豸ʱ���ص��豸�����
	//			szLabel	[IN] �豸��ǩ�ַ��������ַ���ӦС��32�ֽڡ�
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_SetLabel(DEVHANDLE hDev, LPSTR szLabel);

	//7.1.9	��ȡ�豸��Ϣ
	//����ԭ��	ULONG DEVAPI SKF_GetDevInfo (DEVHANDLE hDev, DEVINFO *pDevInfo)
	//��������	��ȡ�豸��һЩ������Ϣ�������豸��ǩ��������Ϣ��֧�ֵ��㷨�ȡ�
	//����		hDev		[IN] �����豸ʱ���ص��豸�����
	//			pDevInfo	[OUT] �����豸��Ϣ��
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_GetDevInfo(DEVHANDLE hDev, DEVINFO *pDevInfo);

	//7.1.10	�����豸
	//����ԭ��	ULONG DEVAPI SKF_LockDev (DEVHANDLE hDev, ULONG ulTimeOut)
	//��������	����豸�Ķ�ռʹ��Ȩ��
	//����		hDev		[IN] �����豸ʱ���ص��豸�����
	//			ulTimeOut	[IN] ��ʱʱ�䣬��λΪ���롣���Ϊ0xFFFFFFFF��ʾ���޵ȴ���
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_LockDev(DEVHANDLE hDev, ULONG ulTimeOut);

	//7.1.11	�����豸
	//����ԭ��	ULONG DEVAPI SKF_UnlockDev (DEVHANDLE hDev)
	//��������	�ͷŶ��豸�Ķ�ռʹ��Ȩ��
	//����		hDev	[IN] �����豸ʱ���ص��豸�����
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_UnlockDev(DEVHANDLE hDev);

	//7.1.12	�豸�����
	//����ԭ��	ULONG DEVAPI SKF_Transmit(DEVHANDLE hDev, BYTE* pbCommand, ULONG ulCommandLen,BYTE* pbData, ULONG* pulDataLen)
	//��������	������ֱ�ӷ��͸��豸�������ؽ����
	//����		hDev			[IN] �豸�����
	//			pbCommand		[IN] �豸���
	//			ulCommandLen	[IN] ����ȡ�
	//			pbData			[OUT] ���ؽ�����ݡ�
	//			pulDataLen		[IN��OUT] ����ʱ��ʾ������ݻ��������ȣ����ʱ��ʾ�������ʵ�ʳ��ȡ�
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_Transmit(DEVHANDLE hDev, BYTE* pbCommand, ULONG ulCommandLen,BYTE* pbData, ULONG* pulDataLen);

	//7.2	���ʿ���
	//���ʿ�����Ҫ����豸��֤��PIN�����Ͱ�ȫ״̬����Ȳ�����

	//7.2.2	�޸��豸��֤��Կ
	//����ԭ��	ULONG DEVAPI SKF_ChangeDevAuthKey (DEVHANDLE hDev, BYTE *pbKeyValue�� ULONG ulKeyLen)
	//��������	�����豸��֤��Կ��
	//����		hDev		[IN] ����ʱ���ص��豸�����
	//			pbKeyValue	[IN] ��Կֵ��
	//			ulKeyLen 	[IN] ��Կ���ȡ�
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	//��ע		Ȩ��Ҫ���豸��֤�ɹ������ʹ�á�
	ULONG DEVAPI SKF_ChangeDevAuthKey(DEVHANDLE hDev, BYTE *pbKeyValue, ULONG ulKeyLen);

	//7.2.3	�豸��֤
	//����ԭ��	ULONG DEVAPI SKF_DevAuth (DEVHANDLE hDev, BYTE *pbAuthData��ULONG ulLen)
	//��������	�豸��֤���豸��Ӧ�ó������֤����֤���̲μ�8.2.3��
	//����		hDev		[IN] ����ʱ���ص��豸�����
	//			pbAuthData	[IN] ��֤���ݡ�
	//			ulLen		[IN] ��֤���ݵĳ��ȡ�
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_DevAuth(DEVHANDLE hDev, BYTE *pbAuthData, ULONG ulLen);

	//7.2.4	�޸�PIN 
	//����ԭ��	ULONG DEVAPI SKF_ChangePIN (HAPPLICATION hApplication, ULONG ulPINType, LPSTR szOldPin, LPSTR szNewPin, ULONG *pulRetryCount)
	//��������	���øú��������޸�Administrator PIN��User PIN��ֵ��
	//			���ԭPIN���������֤ʧ�ܣ��ú����᷵����ӦPIN���ʣ�����Դ�������ʣ�����Ϊ0ʱ����ʾPIN�Ѿ���������
	//����		hApplication	[IN] Ӧ�þ����
	//			ulPINType		[IN] PIN���ͣ���ΪADMIN_TYPE��USER_TYPE��
	//			szOldPin		[IN] ԭPINֵ��
	//			szNewPin		[IN] ��PINֵ��
	//			pulRetryCount	[OUT] ��������Դ�����
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_ChangePIN(HAPPLICATION hApplication, ULONG ulPINType, LPSTR szOldPin, LPSTR szNewPin, ULONG *pulRetryCount);

	//7.2.5	��ȡPIN��Ϣ
	//����ԭ��	ULONG DEVAPI SKF_GetPINInfo(HAPPLICATION hApplication, ULONG  ulPINType, ULONG *pulMaxRetryCount, ULONG *pulRemainRetryCount, BOOL *pbDefaultPin)
	//��������	��ȡPIN����Ϣ������������Դ�������ǰʣ�����Դ������Լ���ǰPIN���Ƿ�Ϊ����Ĭ��PIN�롣
	//����		hApplication		[IN] Ӧ�þ����
	//			ulPINType			[IN] PIN���͡�
	//			pulMaxRetryCount	[OUT] ������Դ�����
	//			pulRemainRetryCount	[OUT] ��ǰʣ�����Դ�������Ϊ0ʱ��ʾ��������
	//			pbDefaultPin		[OUT] �Ƿ�Ϊ����Ĭ��PIN�롣
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_GetPINInfo(HAPPLICATION hApplication, ULONG  ulPINType, ULONG *pulMaxRetryCount, ULONG *pulRemainRetryCount, BOOL *pbDefaultPin);

	//7.2.6	У��PIN 
	//����ԭ��	ULONG DEVAPI SKF_VerifyPIN (HAPPLICATION hApplication, ULONG  ulPINType, LPSTR szPIN, ULONG *pulRetryCount)
	//��������	У��PIN�롣У��ɹ��󣬻�����Ӧ��Ȩ�ޣ����PIN����󣬻᷵��PIN������Դ����������Դ���Ϊ0ʱ��ʾPIN���Ѿ�������
	//����		hApplication	[IN] Ӧ�þ����
	//			ulPINType		[IN] PIN���͡�
	//			szPIN			[IN] PINֵ��
	//			pulRetryCount	[OUT] ����󷵻ص����Դ�����
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_VerifyPIN(HAPPLICATION hApplication, ULONG  ulPINType, LPSTR szPIN, ULONG *pulRetryCount);

	//7.2.7	����PIN 
	//����ԭ��	ULONG DEVAPI SKF_UnblockPIN (HAPPLICATION hApplication, LPSTR szAdminPIN, LPSTR szNewUserPIN,  ULONG *pulRetryCount)
	//��������	���û���PIN��������ͨ�����øú����������û�PIN�롣
	//			�������û�PIN�뱻���ó���ֵ���û�PIN������Դ���Ҳ�ָ���ԭֵ��
	//����		hApplication	[IN] Ӧ�þ����
	//			szAdminPIN		[IN] ����ԱPIN�롣
	//			szNewUserPIN	[IN] �µ��û�PIN�롣
	//			pulRetryCount	[OUT] ����ԱPIN�����ʱ������ʣ�����Դ�����
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	//��ע		��֤�����ԱPIN���ܹ������û�PIN�룬��������Administrator PIN����ȷ�����Ѿ������������ʧ�ܣ�������Administrator PIN�����Դ�����
	ULONG DEVAPI SKF_UnblockPIN(HAPPLICATION hApplication, LPSTR szAdminPIN, LPSTR szNewUserPIN,  ULONG *pulRetryCount);

	//7.2.8	���Ӧ�ð�ȫ״̬
	//����ԭ��	ULONG DEVAPI SKF_ClearSecureState (HAPPLICATION hApplication)
	//��������	���Ӧ�õ�ǰ�İ�ȫ״̬��
	//����		hApplication	[IN] Ӧ�þ����
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_ClearSecureState(HAPPLICATION hApplication);

	//7.3	Ӧ�ù���
	//Ӧ�ù�����Ҫ���Ӧ�õĴ�����ö�١�ɾ�����򿪡��رյȲ���

	//7.3.2	����Ӧ��
	//����ԭ��	ULONG DEVAPI SKF_CreateApplication(DEVHANDLE hDev, LPSTR szAppName, LPSTR szAdminPin, DWORD dwAdminPinRetryCount,LPSTR szUserPin, DWORD dwUserPinRetryCount,DWORD dwCreateFileRights, HAPPLICATION *phApplication)
	//��������	����һ��Ӧ�á� 
	//����		hDev					[IN] �����豸ʱ���ص��豸�����
	//			szAppName				[IN] Ӧ�����ơ�
	//			szAdminPin				[IN] ����ԱPIN��
	//			dwAdminPinRetryCount	[IN] ����ԱPIN������Դ�����
	//			szUserPin				[IN] �û�PIN��
	//			dwUserPinRetryCount		[IN] �û�PIN������Դ�����
	//			dwCreateFileRights		[IN] �ڸ�Ӧ���´����ļ���������Ȩ�ޣ��μ�6.4.9Ȩ�����͡�Ϊ����Ȩ�޵Ļ�ֵ��
	//			phApplication			[OUT] Ӧ�õľ����
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	//��ע		Ȩ��Ҫ����Ҫ�豸Ȩ�ޡ�
	ULONG DEVAPI SKF_CreateApplication(DEVHANDLE hDev, LPSTR szAppName, LPSTR szAdminPin, DWORD dwAdminPinRetryCount,LPSTR szUserPin, DWORD dwUserPinRetryCount,DWORD dwCreateFileRights, HAPPLICATION *phApplication);

	//7.3.3	ö��Ӧ��
	//����ԭ��	ULONG DEVAPI SKF_EnumApplication(DEVHANDLE hDev, LPSTR szAppName,ULONG *pulSize)
	//��������	ö���豸�д��ڵ�����Ӧ�á�
	//����		hDev		[IN] �����豸ʱ���ص��豸�����
	//			szAppName	[OUT] ����Ӧ�������б�, ����ò���Ϊ�գ�����pulSize��������Ҫ���ڴ�ռ��С��ÿ��Ӧ�õ������Ե���'\0'��������˫'\0'��ʾ�б�Ľ�����
	//			pulSize		[IN��OUT] ����ʱ��ʾӦ�����ƵĻ��������ȣ����ʱ����szAppName��ռ�õĿռ��С��
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_EnumApplication(DEVHANDLE hDev, LPSTR szAppName,ULONG *pulSize);

	//7.3.4	ɾ��Ӧ��
	//����ԭ��	ULONG DEVAPI SKF_DeleteApplication(DEVHANDLE hDev, LPSTR szAppName)
	//��������	ɾ��ָ����Ӧ�á�
	//����		hDev		[IN] �����豸ʱ���ص��豸�����
	//			szAppName	[IN] Ӧ�����ơ�
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	//��ע		Ȩ��Ҫ����Ҫ�豸Ȩ�ޡ�
	ULONG DEVAPI SKF_DeleteApplication(DEVHANDLE hDev, LPSTR szAppName);

	//7.3.5	��Ӧ��
	//����ԭ��	ULONG DEVAPI SKF_OpenApplication(DEVHANDLE hDev, LPSTR szAppName, HAPPLICATION *phApplication)
	//��������	��ָ����Ӧ�á�
	//����		hDev			[IN] �����豸ʱ���ص��豸�����
	//			szAppName		[IN] Ӧ�����ơ�
	//			phApplication	[OUT] Ӧ�õľ����
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_OpenApplication(DEVHANDLE hDev, LPSTR szAppName, HAPPLICATION *phApplication);

	//7.3.6	�ر�Ӧ��
	//����ԭ��	ULONG DEVAPI SKF_CloseApplication(HAPPLICATION hApplication)
	//��������	�ر�Ӧ�ò��ͷ�Ӧ�þ����
	//����		hApplication	[IN]Ӧ�þ����
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	//��ע		�˺�����Ӱ��Ӧ�ð�ȫ״̬��
	ULONG DEVAPI SKF_CloseApplication(HAPPLICATION hApplication);

	//7.4	�ļ�����
	//7.4.1	����
	//�ļ����������������û���չ��������Ҫ�����������ļ���ɾ���ļ���ö���ļ�����ȡ�ļ���Ϣ���ļ���д�Ȳ�����

	//7.4.2	�����ļ�
	//����ԭ��	ULONG DEVAPI SKF_CreateFile (HAPPLICATION hApplication, LPSTR szFileName, ULONG ulFileSize, ULONG ulReadRights��ULONG ulWriteRights)
	//��������	�����ļ�ʱҪָ���ļ������ƣ���С���Լ��ļ��Ķ�дȨ�ޡ�
	//����		hApplication	[IN] Ӧ�þ����
	//			szFileName		[IN] �ļ����ƣ����Ȳ��ô���32���ֽڡ�
	//			ulFileSize		[IN] �ļ���С��
	//			ulReadRights	[IN] �ļ���Ȩ�ޣ��μ�6.4.9 Ȩ�����͡���Ϊ����Ȩ�޵Ļ�ֵ��
	//			ulWriteRights	[IN] �ļ�дȨ�ޣ��μ�6.4.9Ȩ�����͡���Ϊ����Ȩ�޵Ļ�ֵ��
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	//��ע		�����ļ���ҪӦ��ָ���Ĵ����ļ�Ȩ�ޡ�
	ULONG DEVAPI SKF_CreateFile(HAPPLICATION hApplication, LPSTR szFileName, ULONG ulFileSize, ULONG ulReadRights, ULONG ulWriteRights);

	//7.4.3	ɾ���ļ�
	//����ԭ��	ULONG DEVAPI SKF_DeleteFile (HAPPLICATION hApplication, LPSTR szFileName)
	//��������	ɾ��ָ���ļ���
	//�ļ�ɾ�����ļ���д���������Ϣ����ʧ��
	//�ļ����豸�е�ռ�õĿռ佫���ͷš�
	//����		hApplication	[IN] Ҫɾ���ļ����ڵ�Ӧ�þ����
	//			szFileName		[IN] Ҫɾ���ļ������ơ�
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	//��ע		Ȩ��Ҫ��ɾ��һ���ļ�Ӧ���жԸ��ļ��Ĵ���Ȩ�ޡ�
	ULONG DEVAPI SKF_DeleteFile(HAPPLICATION hApplication, LPSTR szFileName);

	//7.4.4	ö���ļ�
	//����ԭ��	ULONG DEVAPI SKF_EnumFiles (HAPPLICATION hApplication, LPSTR szFileList, ULONG *pulSize)
	//��������	ö��һ��Ӧ���´��ڵ������ļ���
	//����		hApplication	[IN] Ӧ�þ����
	//			szFileList		[OUT] �����ļ������б��ò���Ϊ�գ���pulSize�����ļ���Ϣ����Ҫ�Ŀռ��С��ÿ���ļ������Ե���'\0'��������˫'\0'��ʾ�б�Ľ�����
	//			pulSize			[IN��OUT] ����ʱ��ʾ���ݻ������Ĵ�С�����ʱ��ʾʵ���ļ������б�ĳ��ȡ�
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_EnumFiles(HAPPLICATION hApplication, LPSTR szFileList, ULONG *pulSize);

	//7.4.5	��ȡ�ļ�����
	//����ԭ��	ULONG DEVAPI SKF_GetFileInfo (HAPPLICATION hApplication, LPSTR szFileName, FILEATTRIBUTE *pFileInfo)
	//��������	��ȡ�ļ���Ϣ��
	//��ȡӦ���ļ���������Ϣ�������ļ��Ĵ�С��Ȩ�޵ȡ�
	//����		hApplication	[IN] �ļ�����Ӧ�õľ����
	//			szFileName		[IN] �ļ����ơ�
	//			pFileInfo		[OUT] �ļ���Ϣ��ָ���ļ����Խṹ��ָ�롣
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_GetFileInfo(HAPPLICATION hApplication, LPSTR szFileName, FILEATTRIBUTE *pFileInfo);

	//7.4.6	���ļ�
	//����ԭ��	ULONG DEVAPI SKF_ReadFile(HAPPLICATION hApplication�� LPSTR szFileName, ULONG ulOffset, ULONG ulSize, BYTE * pbOutData, ULONG *pulOutLen)
	//��������	��ȡ�ļ����ݡ�
	//����		hApplication	[IN] Ӧ�þ����
	//			szFileName		[IN] �ļ�����
	//			ulOffset		[IN] �ļ���ȡƫ��λ�á�
	//			ulSize			[IN] Ҫ��ȡ�ĳ��ȡ�
	//			pbOutData		[OUT] �������ݵĻ�������
	//			pulOutLen		[IN��OUT]����ʱ��ʾ�����Ļ�������С�����ʱ��ʾʵ�ʶ�ȡ���ص����ݴ�С��
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	//��ע		Ȩ��Ҫ����߱��Ը��ļ��Ķ�Ȩ�ޡ�
	ULONG DEVAPI SKF_ReadFile(HAPPLICATION hApplication, LPSTR szFileName, ULONG ulOffset, ULONG ulSize, BYTE * pbOutData, ULONG *pulOutLen);

	//7.4.7	д�ļ�
	//����ԭ��	ULONG DEVAPI SKF_WriteFile (HAPPLICATION hApplication, LPSTR szFileName, ULONG  ulOffset, BYTE *pbInData, ULONG ulSize)
	//��������	д���ݵ��ļ��С�
	//����		hApplication	[IN] Ӧ�þ����
	//			szFileName		[IN] �ļ�����
	//			ulOffset		[IN] д���ļ���ƫ������
	//			pbData			[IN] д�����ݻ�������
	//			ulSize			[IN] д�����ݵĴ�С��
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	//��ע		Ȩ��Ҫ����߱����ļ���дȨ�ޡ�
	ULONG DEVAPI SKF_WriteFile(HAPPLICATION hApplication, LPSTR szFileName, ULONG  ulOffset, BYTE *pbInData, ULONG ulSize);

	//7.5	��������
	//7.5.1	����
	//���淶�ṩ��Ӧ�ù�������������ֲ�ͬӦ�õĹ�������������ɾ����ö�١��򿪺͹ر������Ĳ�����

	//7.5.2	��������
	//����ԭ��	ULONG DEVAPI SKF_CreateContainer (HAPPLICATION hApplication, LPSTR szContainerName, HCONTAINER *phContainer)
	//��������	��Ӧ���½���ָ�����Ƶ��������������������
	//����		hApplication	[IN] Ӧ�þ����
	//			szContainerName	[IN] ASCII�ַ�������ʾ���������������ƣ��������Ƶ���󳤶Ȳ��ܳ���64�ֽڡ�
	//			phContainer		[OUT] �������������������������
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	//��ע		Ȩ��Ҫ����Ҫ�û�Ȩ�ޡ�
	ULONG DEVAPI SKF_CreateContainer(HAPPLICATION hApplication, LPSTR szContainerName, HCONTAINER *phContainer);

	//7.5.3	ɾ������
	//����ԭ��	ULONG DEVAPI SKF_DeleteContainer(HAPPLICATION hApplication, LPSTR szContainerName)
	//��������	��Ӧ����ɾ��ָ�����Ƶ��������ͷ�������ص���Դ��
	//����		hApplication	[IN] Ӧ�þ����
	//			szContainerName	[IN] ָ��ɾ�����������ơ�
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	//��ע		Ȩ��Ҫ����Ҫ�û�Ȩ�ޡ�
	ULONG DEVAPI SKF_DeleteContainer(HAPPLICATION hApplication, LPSTR szContainerName);

	//7.5.4	������
	//����ԭ��	ULONG DEVAPI SKF_OpenContainer(HAPPLICATION hApplication,LPSTR szContainerName,HCONTAINER *phContainer)
	//��������	��ȡ���������
	//����		hApplication	[IN] Ӧ�þ����
	//			szContainerName	[IN] ���������ơ�
	//			phContainer		[OUT] �������������ľ����
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_OpenContainer(HAPPLICATION hApplication,LPSTR szContainerName,HCONTAINER *phContainer);

	//7.5.5	�ر�����
	//����ԭ��	ULONG DEVAPI SKF_CloseContainer(HCONTAINER hContainer)
	//��������	�ر�������������ͷ�������������Դ��
	//����		hContainer	[IN] ���������
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_CloseContainer(HCONTAINER hContainer);

	//7.5.6	ö������
	//����ԭ��	ULONG DEVAPI SKF_EnumContainer (HAPPLICATION hApplication,LPSTR szContainerName,ULONG *pulSize)
	//��������	ö��Ӧ���µ������������������������б�
	//����		hApplication	[IN] Ӧ�þ����
	//			szContainerName	[OUT] ָ�����������б�����������˲���ΪNULLʱ��pulSize��ʾ������������Ҫ�������ĳ��ȣ�����˲�����ΪNULLʱ���������������б�ÿ���������Ե���'\0'Ϊ�������б���˫'\0'������ 
	//			pulSize			[IN��OUT] ����ʱ��ʾszContainerName�������ĳ��ȣ����ʱ��ʾ���������б�ĳ��ȡ�
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_EnumContainer(HAPPLICATION hApplication,LPSTR szContainerName,ULONG *pulSize);

	//7.5.7	�����������
	//����ԭ��	ULONG DEVAPI SKF_GetContainerType(HCONTAINER hContainer, ULONG *pulContainerType)
	//��������	��ȡ����������
	//����		hContainer			[IN] ���������
	//			pulContainerType	[OUT] ��õ��������͡�ָ��ָ���ֵΪ0��ʾδ������δ�������ͻ���Ϊ��������Ϊ1��ʾΪRSA������Ϊ2��ʾΪECC������
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_GetContainerType(HCONTAINER hContainer, ULONG *pulContainerType);

	//7.5.8	��������֤��
	//����ԭ��	ULONG DEVAPI SKF_ImportCertificate(HCONTAINER hContainer, BOOL bSignFlag,  BYTE* pbCert, ULONG ulCertLen)
	//��������	�������ڵ�������֤�顣
	//����		hContainer	[IN] ���������
	//			bSignFlag	[IN] TRUE��ʾǩ��֤�飬FALSE��ʾ����֤�顣
	//			pbCert		[IN] ָ��֤�����ݻ�������
	//			ulCertLen	[IN] ֤�鳤�ȡ�
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_ImportCertificate(HCONTAINER hContainer, BOOL bSignFlag,  BYTE* pbCert, ULONG ulCertLen);

	//7.5.9	��������֤��
	//����ԭ��	ULONG DEVAPI SKF_ExportCertificate(HCONTAINER hContainer, BOOL bSignFlag,  BYTE* pbCert, ULONG *pulCertLen)
	//��������	�������ڵ�������֤�顣
	//����		hContainer	[IN] ���������
	//			bSignFlag	[IN] TRUE��ʾǩ��֤�飬FALSE��ʾ����֤�顣
	//			pbCert		[OUT] ָ��֤�����ݻ�����������˲���ΪNULLʱ��pulCertLen��ʾ������������Ҫ�������ĳ��ȣ�����˲�����ΪNULLʱ����������֤�����ݡ�
	//			pulCertLen	[IN/OUT] ����ʱ��ʾpbCert�������ĳ��ȣ����ʱ��ʾ֤�����ݵĳ��ȡ�
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_ExportCertificate(HCONTAINER hContainer, BOOL bSignFlag,  BYTE* pbCert, ULONG *pulCertLen);

	//7.6	�������
	//7.6.1	����
	//����������ṩ�Գ��㷨���㡢�ǶԳ��㷨���㡢�����Ӵ����㡢��Կ������Ϣ���������ȹ��ܡ�

	//7.6.2	���������
	//����ԭ��	ULONG DEVAPI SKF_GenRandom (DEVHANDLE hDev, BYTE *pbRandom,ULONG ulRandomLen)
	//��������	����ָ�����ȵ��������
	//����		hDev		[IN] �豸�����
	//			pbRandom	[OUT]���ص��������
	//			ulRandomLen	[IN] ��������ȡ�
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_GenRandom(DEVHANDLE hDev, BYTE *pbRandom,ULONG ulRandomLen);

	//7.6.3	�����ⲿRSA��Կ��
	//����ԭ��	ULONG DEVAPI SKF_GenExtRSAKey (DEVHANDLE hDev, ULONG ulBitsLen, RSAPRIVATEKEYBLOB *pBlob)
	//��������	���豸����RSA��Կ�Բ����������
	//����		hDev		[IN]�豸�����
	//			ulBitsLen	[IN] ��Կģ����
	//			pBlob		[OUT] ���ص�˽Կ���ݽṹ��
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	//��ע��	���ɵ�˽Կֻ����������ӿ��ڲ��������ͼ��㡣
	ULONG DEVAPI SKF_GenExtRSAKey(DEVHANDLE hDev, ULONG ulBitsLen, RSAPRIVATEKEYBLOB *pBlob);

	//7.6.4	����RSAǩ����Կ��
	//����ԭ��	ULONG DEVAPI SKF_GenRSAKeyPair (HCONTAINER hContainer, ULONG ulBitsLen, RSAPUBLICKEYBLOB *pBlob)
	//��������	����RSAǩ����Կ�Բ����ǩ����Կ��
	//����		hContainer	[IN] ���������
	//			ulBitsLen	[IN] ��Կģ����
	//			pBlob		[OUT] ���ص�RSA��Կ���ݽṹ��
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	//��ע		Ȩ��Ҫ����Ҫ�û�Ȩ�ޡ�
	ULONG DEVAPI SKF_GenRSAKeyPair(HCONTAINER hContainer, ULONG ulBitsLen, RSAPUBLICKEYBLOB *pBlob);

	//7.6.5	����RSA������Կ��
	//����ԭ��	ULONG DEVAPI SKF_ImportRSAKeyPair (
	//												HCONTAINER hContainer, ULONG ulSymAlgId, 
	//												BYTE *pbWrappedKey, ULONG ulWrappedKeyLen,
	//												BYTE *pbEncryptedData, ULONG ulEncryptedDataLen)
	//��������	����RSA���ܹ�˽Կ�ԡ�
	//����		hContainer			[IN] ���������
	//			ulSymAlgId			[IN] �Գ��㷨��Կ��ʶ��
	//			pbWrappedKey		[IN] ʹ�ø�������ǩ����Կ�����ĶԳ��㷨��Կ��
	//			ulWrappedKeyLen		[IN] �����ĶԳ��㷨��Կ���ȡ�
	//			pbEncryptedData		[IN] �Գ��㷨��Կ������RSA����˽Կ��˽Կ�ĸ�ʽ��ѭPKCS #1 v2.1: RSA Cryptography Standard�е�˽Կ��ʽ���塣
	//			ulEncryptedDataLen	[IN] �Գ��㷨��Կ������RSA���ܹ�˽Կ�Գ��ȡ�
	//����ֵ	SAR_OK��			�ɹ���
	//������	�����롣
	//��ע		Ȩ��Ҫ����Ҫ�û�Ȩ�ޡ�
	ULONG DEVAPI SKF_ImportRSAKeyPair(HCONTAINER hContainer, ULONG ulSymAlgId, 
		BYTE *pbWrappedKey, ULONG ulWrappedKeyLen,
		BYTE *pbEncryptedData, ULONG ulEncryptedDataLen);

	//7.6.6	RSAǩ��
	//����ԭ��	ULONG DEVAPI SKF_RSASignData(HCONTAINER hContainer, BYTE *pbData, ULONG  ulDataLen, BYTE *pbSignature, ULONG *pulSignLen)
	//��������	ʹ��hContainerָ��������ǩ��˽Կ����ָ������pbData��������ǩ����ǩ����Ľ����ŵ�pbSignature������������pulSignLenΪǩ���ĳ��ȡ�
	//����		hContainer	[IN] ����ǩ����˽Կ�������������
	//			pbData		[IN] ��ǩ�������ݡ�
	//			ulDataLen	[IN] ǩ�����ݳ��ȣ�Ӧ������RSA��Կģ��-11��
	//			pbSignature	[OUT] ���ǩ������Ļ�����ָ�룬���ֵΪNULL������ȡ��ǩ��������ȡ�
	//			pulSignLen	[IN��OUT] ����ʱ��ʾǩ�������������С�����ʱ��ʾǩ��������ȡ�
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	//��ע		Ȩ��Ҫ����Ҫ�û�Ȩ�ޡ�
	ULONG DEVAPI SKF_RSASignData(HCONTAINER hContainer, BYTE *pbData, ULONG  ulDataLen, BYTE *pbSignature, ULONG *pulSignLen);

	//7.6.7	RSA��ǩ
	//����ԭ��	ULONG DEVAPI SKF_RSAVerify (DEVHANDLE hDev , RSAPUBLICKEYBLOB* pRSAPubKeyBlob, BYTE *pbData, ULONG  ulDataLen, BYTE *pbSignature, ULONG ulSignLen)
	//��������	��֤RSAǩ������pRSAPubKeyBlob�ڵĹ�Կֵ�Դ���ǩ���ݽ�����ǩ��
	//����		hDev			[IN] �豸�����
	//			pRSAPubKeyBlob	[IN] RSA��Կ���ݽṹ��
	//			pbData			[IN] ����֤ǩ�������ݡ�
	//			ulDataLen		[IN] ���ݳ��ȣ�Ӧ�����ڹ�Կģ��-11��
	//			pbSignature		[IN] ����֤��ǩ��ֵ��
	//			ulSignLen		[IN] ǩ��ֵ���ȣ�����Ϊ��Կģ����
	//����ֵ	SAR_OK��		�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_RSAVerify(DEVHANDLE hDev , RSAPUBLICKEYBLOB* pRSAPubKeyBlob, BYTE *pbData, ULONG  ulDataLen, BYTE *pbSignature, ULONG ulSignLen);

	//7.6.8	RSA���ɲ������Ự��Կ
	//����ԭ��	ULONG DEVAPI SKF_RSAExportSessionKey (HCONTAINER hContainer, ULONG ulAlgId, RSAPUBLICKEYBLOB *pPubKey, BYTE *pbData, ULONG  *pulDataLen, HANDLE *phSessionKey)
	//��������	���ɻỰ��Կ�����ⲿRSA��Կ���������
	//����		hContainer	[IN] ���������
	//			ulAlgId		[IN] �Ự��Կ�㷨��ʶ��
	//			pPubKey		[IN] ���ܻỰ��Կ��RSA��Կ���ݽṹ��
	//			pbData		[OUT] �����ļ��ܻỰ��Կ���ģ�����PKCS#1v1.5Ҫ���װ��
	//			pulDataLen	[IN��OUT] ����ʱ��ʾ�Ự��Կ�������ݻ��������ȣ����ʱ��ʾ�Ự��Կ���ĵ�ʵ�ʳ��ȡ�
	//			phSessionKey[OUT] ��������Կ�����
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_RSAExportSessionKey(HCONTAINER hContainer, ULONG ulAlgId, RSAPUBLICKEYBLOB *pPubKey, BYTE *pbData, ULONG  *pulDataLen, HANDLE *phSessionKey);

	//7.6.9	RSA������Կ����
	//����ԭ��	ULONG DEVAPI SKF_ExtRSAPubKeyOperation (DEVHANDLE hDev, RSAPUBLICKEYBLOB* pRSAPubKeyBlob,BYTE* pbInput, ULONG ulInputLen, BYTE* pbOutput, ULONG* pulOutputLen)
	//��������	ʹ���ⲿ�����RSA��Կ��������������Կ���㲢��������
	//����		hDev			[IN] �豸�����
	//			pRSAPubKeyBlob	[IN] RSA��Կ���ݽṹ��
	//			pbInput			[IN] ָ��������ԭʼ���ݻ�������
	//			ulInputLen		[IN] ������ԭʼ���ݵĳ��ȣ�����Ϊ��Կģ����
	//			pbOutput		[OUT] ָ��RSA��Կ������������������ò���ΪNULL������pulOutputLen������������ʵ�ʳ��ȡ�
	//			pulOutputLen	[IN��OUT] ����ʱ��ʾpbOutput�������ĳ��ȣ����ʱ��ʾRSA��Կ��������ʵ�ʳ��ȡ�
	//����ֵ	SAR_OK��		�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_ExtRSAPubKeyOperation(DEVHANDLE hDev, RSAPUBLICKEYBLOB* pRSAPubKeyBlob,BYTE* pbInput, ULONG ulInputLen, BYTE* pbOutput, ULONG* pulOutputLen);

	//7.6.10	RSA����˽Կ����
	//����ԭ��	ULONG DEVAPI SKF_ExtRSAPriKeyOperation (DEVHANDLE hDev, RSAPRIVATEKEYBLOB* pRSAPriKeyBlob,BYTE* pbInput, ULONG ulInputLen, BYTE* pbOutput, ULONG* pulOutputLen)
	//��������	ֱ��ʹ���ⲿ�����RSA˽Կ������������˽Կ���㲢��������
	//����		hDev			[IN] �豸�����
	//			pRSAPriKeyBlob	[IN] RSA˽Կ���ݽṹ��
	//			pbInput			[IN] ָ����������ݻ�������
	//			ulInputLen		[IN] ���������ݵĳ��ȣ�����Ϊ��Կģ����
	//			pbOutput		[OUT] RSA˽Կ������������ò���ΪNULL������pulOutputLen������������ʵ�ʳ��ȡ�
	//			pulOutputLen	[IN��OUT] ����ʱ��ʾpbOutput�������ĳ��ȣ����ʱ��ʾRSA˽Կ��������ʵ�ʳ��ȡ�
	//����ֵ	SAR_OK��		�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_ExtRSAPriKeyOperation(DEVHANDLE hDev, RSAPRIVATEKEYBLOB* pRSAPriKeyBlob,BYTE* pbInput, ULONG ulInputLen, BYTE* pbOutput, ULONG* pulOutputLen);

	//7.6.11	����ECCǩ����Կ��
	//����ԭ��	ULONG DEVAPI SKF_GenECCKeyPair (HCONTAINER hContainer, ULONG ulAlgId�� ECCPUBLICKEYBLOB *pBlob)
	//��������	����ECCǩ����Կ�Բ����ǩ����Կ��
	//����		hContainer	[IN] ��Կ���������
	//			ulAlgId		[IN] �㷨��ʶ��ֻ֧��SGD_SM2_1�㷨��
	//			pBlob		[OUT] ����ECC��Կ���ݽṹ��
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	//��ע		Ȩ��Ҫ����Ҫ�û�Ȩ�ޡ�
	ULONG DEVAPI SKF_GenECCKeyPair(HCONTAINER hContainer, ULONG ulAlgId, ECCPUBLICKEYBLOB *pBlob);

	//7.6.12	����ECC������Կ��
	//����ԭ��	ULONG DEVAPI SKF_ImportECCKeyPair(HCONTAINER hContainer, PENVELOPEDKEYBLOB pEnvelopedKeyBlob)
	//��������	����ECC��˽Կ�ԡ�
	//����		hContainer			[IN] ��Կ���������
	//			pEnvelopedKeyBlob	[IN] �ܱ����ļ�����Կ�ԡ�
	//����ֵ	SAR_OK��			�ɹ���
	//������	�����롣
	//��ע		Ȩ��Ҫ����Ҫ�û�Ȩ�ޡ�
	ULONG DEVAPI SKF_ImportECCKeyPair(HCONTAINER hContainer, PENVELOPEDKEYBLOB pEnvelopedKeyBlob);

	//7.6.13	ECCǩ��
	//����ԭ��	ULONG DEVAPI SKF_ECCSignData (HCONTAINER hContainer, BYTE *pbData, ULONG  ulDataLen, PECCSIGNATUREBLOB pSignature)
	//��������	ECC����ǩ��������ECC�㷨��ָ��˽ԿhKey����ָ������pbData��������ǩ����ǩ����Ľ����ŵ�pSignature�С�
	//����		hContainer	[IN] ��Կ���������
	//			pbData		[IN] ��ǩ�������ݡ�
	//			ulDataLen	[IN] ��ǩ�����ݳ��ȣ�����С����Կģ����
	//			pSignature	[OUT] ǩ��ֵ��
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	//��ע		Ȩ��Ҫ����Ҫ�û�Ȩ�ޡ�
	//			��������Ϊ��ǩ���ݵ��Ӵ�ֵ����ʹ��SM2�㷨ʱ������������Ϊ��ǩ���ݾ���SM2ǩ��Ԥ����Ľ����
	//			Ԥ���������ѭ����Կ���������ʩӦ�ü�����ϵ SM2�㷨����ʹ�ù淶����
	ULONG DEVAPI SKF_ECCSignData(HCONTAINER hContainer, BYTE *pbData, ULONG  ulDataLen, PECCSIGNATUREBLOB pSignature);

	//7.6.14	ECC��ǩ
	//����ԭ��	ULONG DEVAPI SKF_ECCVerify (DEVHANDLE hDev , ECCPUBLICKEYBLOB* pECCPubKeyBlob, BYTE *pbData, ULONG  ulDataLen, PECCSIGNATUREBLOB pSignature)
	//��������	��ECC��Կ�����ݽ�����ǩ��
	//����		hDev			[IN] �豸�����
	//			pECCPubKeyBlob	[IN] ECC��Կ���ݽṹ��
	//			pbData			[IN] ����֤ǩ�������ݡ�
	//			ulDataLen		[IN] ���ݳ��ȡ�
	//			pSignature		[IN] ����֤ǩ��ֵ��
	//����ֵ	SAR_OK��		�ɹ���
	//������	�����롣
	//��ע		��������Ϊ��ǩ���ݵ��Ӵ�ֵ����ʹ��SM2�㷨ʱ������������Ϊ��ǩ���ݾ���SM2ǩ��Ԥ����Ľ����
	//			Ԥ���������ѭ����Կ���������ʩӦ�ü�����ϵ SM2�㷨����ʹ�ù淶����
	ULONG DEVAPI SKF_ECCVerify(DEVHANDLE hDev , ECCPUBLICKEYBLOB* pECCPubKeyBlob, BYTE *pbData, ULONG  ulDataLen, PECCSIGNATUREBLOB pSignature);

	//7.6.15	ECC���ɲ������Ự��Կ
	//����ԭ��	ULONG DEVAPI SKF_ECCExportSessionKey (HCONTAINER hContainer, ULONG ulAlgId, ECCPUBLICKEYBLOB *pPubKey, PECCCIPHERBLOB pData, HANDLE *phSessionKey)
	//��������	���ɻỰ��Կ�����ⲿ��Կ���ܵ�����
	//����		hContainer		[IN] ���������
	//			ulAlgId			[IN] �Ự��Կ�㷨��ʶ��
	//			pPubKey			[IN] �ⲿ����Ĺ�Կ�ṹ��
	//			pData			[OUT] �Ự��Կ���ġ�
	//			phSessionKey	[OUT] �Ự��Կ�����
	//����ֵ	SAR_OK��		�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_ECCExportSessionKey(HCONTAINER hContainer, ULONG ulAlgId, ECCPUBLICKEYBLOB *pPubKey, PECCCIPHERBLOB pData, HANDLE *phSessionKey);

	//7.6.16	ECC������Կ����
	//����ԭ��	ULONG DEVAPI SKF_ExtECCEncrypt (DEVHANDLE hDev, ECCPUBLICKEYBLOB*  pECCPubKeyBlob,BYTE* pbPlainText, ULONG ulPlainTextLen, PECCCIPHERBLOB pCipherText)
	//��������	ʹ���ⲿ�����ECC��Կ�������������������㲢��������
	//����		hDev			[IN] �豸�����
	//			pECCPubKeyBlob	[IN] ECC��Կ���ݽṹ��
	//			pbPlainText		[IN] �����ܵ��������ݡ�
	//			ulPlainTextLen	[IN] �������������ݵĳ��ȡ�
	//			pCipherText		[OUT] �������ݡ�
	//����ֵ	SAR_OK��		�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_ExtECCEncrypt(DEVHANDLE hDev, ECCPUBLICKEYBLOB*  pECCPubKeyBlob,BYTE* pbPlainText, ULONG ulPlainTextLen, PECCCIPHERBLOB pCipherText);

	//7.6.17	ECC����˽Կ����
	//����ԭ��	ULONG DEVAPI SKF_ExtECCDecrypt (DEVHANDLE hDev, ECCPRIVATEKEYBLOB*  pECCPriKeyBlob, PECCCIPHERBLOB pCipherText, BYTE* pbPlainText, ULONG* pulPlainTextLen)
	//��������	ʹ���ⲿ�����ECC˽Կ�������������������㲢��������
	//����		hDev			[IN] �豸�����
	//			pECCPriKeyBlob	[IN] ECC˽Կ���ݽṹ��
	//			pCipherText		[IN] �����ܵ��������ݡ�
	//			pbPlainText		[OUT] �����������ݣ�����ò���ΪNULL������pulPlainTextLen�����������ݵ�ʵ�ʳ��ȡ�
	//			pulPlainTextLen	[IN��OUT] ����ʱ��ʾpbPlainText�������ĳ��ȣ����ʱ��ʾ�������ݵ�ʵ�ʳ��ȡ�
	//����ֵ	SAR_OK��		�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_ExtECCDecrypt(DEVHANDLE hDev, ECCPRIVATEKEYBLOB*  pECCPriKeyBlob, PECCCIPHERBLOB pCipherText, BYTE* pbPlainText, ULONG* pulPlainTextLen);

	//7.6.18	ECC����˽Կǩ��
	//����ԭ��	ULONG DEVAPI SKF_ExtECCSign (DEVHANDLE hDev, ECCPRIVATEKEYBLOB*  pECCPriKeyBlob, BYTE* pbData, ULONG ulDataLen, PECCSIGNATUREBLOB pSignature)
	//��������	ʹ���ⲿ�����ECC˽Կ������������ǩ�����㲢��������
	//����		hDev			[IN] �豸�����
	//			pECCPriKeyBlob	[IN] ECC˽Կ���ݽṹ��
	//			pbData			[IN] ��ǩ�����ݡ�
	//			ulDataLen		[IN] ��ǩ�����ݵĳ��ȡ�
	//			pSignature		[OUT]ǩ��ֵ��
	//����ֵ	SAR_OK��		�ɹ���
	//������	�����롣
	//��ע��	��������Ϊ��ǩ���ݵ��Ӵ�ֵ����ʹ��SM2�㷨ʱ������������Ϊ��ǩ���ݾ���SM2ǩ��Ԥ����Ľ����
	//			Ԥ���������ѭ����Կ���������ʩӦ�ü�����ϵ SM2�㷨����ʹ�ù淶����
	ULONG DEVAPI SKF_ExtECCSign(DEVHANDLE hDev, ECCPRIVATEKEYBLOB*  pECCPriKeyBlob, BYTE* pbData, ULONG ulDataLen, PECCSIGNATUREBLOB pSignature);

	//7.6.19	ECC������Կ��ǩ
	//����ԭ��	ULONG DEVAPI SKF_ExtECCVerify (DEVHANDLE hDev, ECCPUBLICKEYBLOB*  pECCPubKeyBlob,BYTE* pbData, ULONG ulDataLen, PECCSIGNATUREBLOB pSignature)
	//��������	�ⲿʹ�ô����ECC��Կ��ǩ����֤��
	//����		hDev			[IN] �豸�����
	//			pECCPubKeyBlob	[IN] ECC��Կ���ݽṹ��
	//			pbData			[IN] ����֤���ݡ�
	//			ulDataLen		[IN] ����֤���ݵĳ��ȡ�
	//			pSignature		[IN] ǩ��ֵ��
	//����ֵ	SAR_OK��		�ɹ���
	//������	�����롣
	//��ע��	��������Ϊ��ǩ���ݵ��Ӵ�ֵ����ʹ��SM2�㷨ʱ������������Ϊ��ǩ���ݾ���SM2ǩ��Ԥ����Ľ����
	//			Ԥ���������ѭ����Կ���������ʩӦ�ü�����ϵ SM2�㷨����ʹ�ù淶����
	ULONG DEVAPI SKF_ExtECCVerify(DEVHANDLE hDev, ECCPUBLICKEYBLOB*  pECCPubKeyBlob,BYTE* pbData, ULONG ulDataLen, PECCSIGNATUREBLOB pSignature);

	//7.6.20	ECC������ԿЭ�̲��������
	//����ԭ��	ULONG DEVAPI SKF_GenerateAgreementDataWithECC (HCONTAINER hContainer, ULONG ulAlgId,ECCPUBLICKEYBLOB*  pTempECCPubKeyBlob,BYTE* pbID, ULONG ulIDLen,HANDLE *phAgreementHandle)
	//��������	ʹ��ECC��ԿЭ���㷨��Ϊ����Ự��Կ������Э�̲�����������ʱECC��Կ�ԵĹ�Կ��Э�̾����
	//����		hContainer			[IN] ���������
	//			ulAlgId				[IN] �Ự��Կ�㷨��ʶ��
	//			pTempECCPubKeyBlob	[OUT] ������ʱECC��Կ��
	//			pbID				[IN] ���𷽵�ID��
	//			ulIDLen				[IN] ����ID�ĳ��ȣ�������32��
	//			phAgreementHandle	[OUT] ���ص���ԿЭ�̾����
	//����ֵ	SAR_OK��			�ɹ���
	//������	�����롣
	//��ע		ΪЭ�̻Ự��Կ��Э�̵ķ���Ӧ���ȵ��ñ�������	
	ULONG DEVAPI SKF_GenerateAgreementDataWithECC(HCONTAINER hContainer, ULONG ulAlgId,ECCPUBLICKEYBLOB*  pTempECCPubKeyBlob,BYTE* pbID, ULONG ulIDLen,HANDLE *phAgreementHandle);

	//7.6.21	ECC����Э�����ݲ�����Ự��Կ
	//����ԭ�ͣ�ULONG DEVAPI SKF_GenerateAgreementDataAndKeyWithECC(
	//														HANDLE hContainer, ULONG ulAlgId,
	//														ECCPUBLICKEYBLOB*  pSponsorECCPubKeyBlob,
	//														ECCPUBLICKEYBLOB*  pSponsorTempECCPubKeyBlob,
	//														ECCPUBLICKEYBLOB*  pTempECCPubKeyBlob,
	//														BYTE* pbID, ULONG ulIDLen, BYTE *pbSponsorID, ULONG ulSponsorIDLen,
	//														HANDLE *phKeyHandle)
	//����������ʹ��ECC��ԿЭ���㷨������Э�̲���������Ự��Կ�������ʱECC��Կ�Թ�Կ�������ز�������Կ�����
	//������	hContainer					[IN] ���������
	//			ulAlgId						[IN] �Ự��Կ�㷨��ʶ��
	//			pSponsorECCPubKeyBlob		[IN] ���𷽵�ECC��Կ��
	//			pSponsorTempECCPubKeyBlob	[IN] ���𷽵���ʱECC��Կ��
	//			pTempECCPubKeyBlob			[OUT] ��Ӧ������ʱECC��Կ��
	//			pbID						[IN] ��Ӧ����ID��
	//			ulIDLen						[IN] ��Ӧ��ID�ĳ��ȣ�������32��
	//			pbSponsorID					[IN] ���𷽵�ID��
	//			ulSponsorIDLen				[IN] ����ID�ĳ��ȣ�������32��
	//			phKeyHandle					[OUT] ���صĶԳ��㷨��Կ�����
	//����ֵ	SAR_OK��					�ɹ���
	//������	�����롣
	//��ע��	����������Ӧ�����á�
	ULONG DEVAPI SKF_GenerateAgreementDataAndKeyWithECC(
		HANDLE hContainer, ULONG ulAlgId,
		ECCPUBLICKEYBLOB*  pSponsorECCPubKeyBlob,
		ECCPUBLICKEYBLOB*  pSponsorTempECCPubKeyBlob,
		ECCPUBLICKEYBLOB*  pTempECCPubKeyBlob,
		BYTE* pbID, ULONG ulIDLen, BYTE *pbSponsorID, ULONG ulSponsorIDLen,
		HANDLE *phKeyHandle);

	//7.6.22	ECC����Ự��Կ
	//����ԭ�ͣ�ULONG DEVAPI SKF_GenerateKeyWithECC (HANDLE hAgreementHandle,
	//												ECCPUBLICKEYBLOB*  pECCPubKeyBlob,
	//												ECCPUBLICKEYBLOB*  pTempECCPubKeyBlob,
	//												BYTE* pbID, ULONG ulIDLen, HANDLE *phKeyHandle)
	//����������ʹ��ECC��ԿЭ���㷨��ʹ������Э�̾������Ӧ����Э�̲�������Ự��Կ��ͬʱ���ػỰ��Կ�����
	//������	hAgreementHandle	[IN] ��ԿЭ�̾����
	//			pECCPubKeyBlob		[IN] �ⲿ�������Ӧ��ECC��Կ��
	//			pTempECCPubKeyBlob	[IN] �ⲿ�������Ӧ����ʱECC��Կ��
	//			pbID				[IN] ��Ӧ����ID��
	//			ulIDLen				[IN] ��Ӧ��ID�ĳ��ȣ�������32��
	//			phKeyHandle			[OUT] ���ص���Կ�����
	//����ֵ	SAR_OK��			�ɹ���
	//������	�����롣
	//��ע��	Э�̵ķ��𷽻����Ӧ����Э�̲�������ñ�����������Ự��Կ��
	//			���������ѭ����Կ���������ʩӦ�ü�����ϵ SM2�㷨����ʹ�ù淶����
	ULONG DEVAPI SKF_GenerateKeyWithECC(HANDLE hAgreementHandle,
		ECCPUBLICKEYBLOB*  pECCPubKeyBlob,
		ECCPUBLICKEYBLOB*  pTempECCPubKeyBlob,
		BYTE* pbID, ULONG ulIDLen, HANDLE *phKeyHandle);

	//7.6.23	������Կ
	//����ԭ��	ULONG DEVAPI SKF_ExportPublicKey (HCONTAINER hContainer, BOOL bSignFlag�� BYTE* pbBlob, ULONG* pulBlobLen)
	//��������	���������е�ǩ����Կ���߼��ܹ�Կ��
	//����		hContainer	[IN] ��Կ���������
	//			bSignFlag	[IN] TRUE��ʾ����ǩ����Կ��FALSE��ʾ�������ܹ�Կ��
	//			pbBlob		[OUT] ָ��RSA��Կ�ṹ��RSAPUBLICKEYBLOB������ECC��Կ�ṹ��ECCPUBLICKEYBLOB����
	//							  ����˲���ΪNULLʱ����pulBlobLen����pbBlob�ĳ��ȡ�
	//			pulBlobLen	[IN��OUT] ����ʱ��ʾpbBlob�������ĳ��ȣ����ʱ��ʾ������Կ�ṹ�Ĵ�С��
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_ExportPublicKey(HCONTAINER hContainer, BOOL bSignFlag, BYTE* pbBlob, ULONG* pulBlobLen);

	//7.6.24	����Ự��Կ
	//����ԭ��	ULONG DEVAPI SKF_ImportSessionKey (HCONTAINER hContainer, ULONG ulAlgId,BYTE *pbWrapedData,ULONG ulWrapedLen��HANDLE *phKey)
	//��������	����Ự��Կ���ģ�ʹ�������еļ���˽Կ���ܵõ��Ự��Կ��
	//����		hContainer		[IN] ���������
	//			ulAlgId			[IN] �Ự��Կ�㷨��ʶ��
	//			pbWrapedData	[IN] Ҫ����ĻỰ��Կ���ġ�������ΪECC����ʱ���˲���ΪECCCIPHERBLOB�������ݣ�������ΪRSA����ʱ���˲���ΪRSA��Կ���ܺ�����ݡ�
	//			ulWrapedLen		[IN] �Ự��Կ���ĳ��ȡ�
	//			phKey			[OUT] ���ػỰ��Կ�����
	//����ֵ	SAR_OK��		�ɹ���
	//������	�����롣
	//��ע		Ȩ��Ҫ����Ҫ�û�Ȩ�ޡ�
	ULONG DEVAPI SKF_ImportSessionKey(HCONTAINER hContainer, ULONG ulAlgId,BYTE *pbWrapedData,ULONG ulWrapedLen, HANDLE *phKey);

	//7.6.25	���ĵ���Ự��Կ
	//����ԭ��	ULONG DEVAPI SKF_SetSymmKey (DEVHANDLE hDev, BYTE* pbKey, ULONG ulAlgID, HANDLE* phKey)
	//��������	�������ĶԳ���Կ��������Կ�����
	//����		hDev		[IN] �豸�����
	//			pbKey		[IN] ָ��Ự��Կֵ�Ļ�������
	//			ulAlgID		[IN] �Ự��Կ�㷨��ʶ��
	//			phKey		[OUT] ���ػỰ��Կ�����
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_SetSymmKey(DEVHANDLE hDev, BYTE* pbKey, ULONG ulAlgID, HANDLE* phKey);

	//7.6.26	���ܳ�ʼ��
	//����ԭ��	ULONG DEVAPI SKF_EncryptInit (HANDLE hKey, BLOCKCIPHERPARAM EncryptParam)
	//��������	���ݼ��ܳ�ʼ�����������ݼ��ܵ��㷨��ز�����
	//����		hKey			[IN] ������Կ�����
	//			EncryptParam	[IN] ���������㷨��ز�������ʼ��������ʼ�������ȡ���䷽��������ֵ��λ���ȡ�
	//����ֵ	SAR_OK��		�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_EncryptInit(HANDLE hKey, BLOCKCIPHERPARAM EncryptParam);

	//7.6.27	�������ݼ���
	//����ԭ��	ULONG DEVAPI SKF_Encrypt(HANDLE hKey, BYTE * pbData, ULONG ulDataLen, BYTE *pbEncryptedData, ULONG *pulEncryptedLen)
	//��������	��һ�������ݵļ��ܲ�������ָ��������Կ��ָ�����ݽ��м��ܣ������ܵ�����ֻ����һ�����飬���ܺ�����ı��浽ָ���Ļ������С�SKF_Encryptֻ�Ե����������ݽ��м��ܣ��ڵ���SKF_Encrypt֮ǰ���������SKF_EncryptInit��ʼ�����ܲ�����SKF_Encypt�ȼ����ȵ���SKF_EncryptUpdate�ٵ���SKF_EncryptFinal��
	//����		hKey 			[IN] ������Կ�����
	//			pbData			[IN] ���������ݡ�
	//			ulDataLen		[IN] ���������ݳ��ȡ�
	//			pbEncryptedData	[OUT] ���ܺ�����ݻ�����ָ�룬����ΪNULL�����ڻ�ü��ܺ����ݳ��ȡ�
	//			pulEncryptedLen	[IN��OUT] ����ʱ��ʾ������ݻ��������ȣ����ʱ��ʾ�������ʵ�ʳ��ȡ�
	//����ֵ	SAR_OK��		�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_Encrypt(HANDLE hKey, BYTE * pbData, ULONG ulDataLen, BYTE *pbEncryptedData, ULONG *pulEncryptedLen);

	//7.6.28	�������ݼ���
	//����ԭ��	ULONG DEVAPI SKF_EncryptUpdate(HANDLE hKey, BYTE * pbData, ULONG ulDataLen, BYTE *pbEncryptedData, ULONG *pulEncryptedLen)
	//��������	����������ݵļ��ܲ�������ָ��������Կ��ָ�����ݽ��м��ܣ������ܵ����ݰ���������飬���ܺ�����ı��浽ָ���Ļ������С�SKF_EncryptUpdate�Զ���������ݽ��м��ܣ��ڵ���SKF_EncryptUpdate֮ǰ���������SKF_EncryptInit��ʼ�����ܲ������ڵ���SKF_EncryptUpdate֮�󣬱������SKF_EncryptFinal�������ܲ�����
	//����		hKey 			[IN] ������Կ�����
	//			pbData			[IN] ���������ݡ�
	//			ulDataLen		[IN] ���������ݳ��ȡ�
	//			pbEncryptedData	[OUT] ���ܺ�����ݻ�����ָ�롣
	//			pulEncryptedLen	[OUT] ���ؼ��ܺ�����ݳ��ȡ�
	//����ֵ	SAR_OK��		�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_EncryptUpdate(HANDLE hKey, BYTE * pbData, ULONG ulDataLen, BYTE *pbEncryptedData, ULONG *pulEncryptedLen);

	//7.6.29	��������
	//����ԭ��	ULONG DEVAPI SKF_EncryptFinal (HANDLE hKey, BYTE *pbEncryptedData, ULONG *ulEncryptedDataLen )
	//��������	��������������ݵļ��ܣ�����ʣ����ܽ�����ȵ���SKF_EncryptInit��ʼ�����ܲ������ٵ���SKF_EncryptUpdate�Զ���������ݽ��м��ܣ�������SKF_EncryptFinal��������������ݵļ��ܡ�
	//����		hKey				[IN] ������Կ�����
	//			pbEncyptedData		[OUT] ���ܽ���Ļ�������
	//			ulEncyptedDataLen	[OUT] ���ܽ���ĳ��ȡ�
	//����ֵ	SAR_OK��			�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_EncryptFinal(HANDLE hKey, BYTE *pbEncryptedData, ULONG *ulEncryptedDataLen );

	//7.6.30	���ܳ�ʼ��
	//����ԭ��	ULONG DEVAPI SKF_DecryptInit (HANDLE hKey, BLOCKCIPHERPARAM DecryptParam)
	//��������	���ݽ��ܳ�ʼ�������ý�����Կ��ز���������SKF_DecryptInit֮�󣬿��Ե���SKF_Decrypt�Ե����������ݽ��н��ܣ�Ҳ���Զ�ε���SKF_DecryptUpdate֮���ٵ���SKF_DecryptFinal��ɶԶ���������ݵĽ��ܡ�
	//����		hKey			[IN] ������Կ�����
	//			DecryptParam	[IN] ���������㷨��ز�������ʼ��������ʼ�������ȡ���䷽��������ֵ��λ���ȡ�
	//����ֵ	SAR_OK��		�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_DecryptInit(HANDLE hKey, BLOCKCIPHERPARAM DecryptParam);

	//7.6.31	�������ݽ���
	//����ԭ��	ULONG DEVAPI SKF_Decrypt(HANDLE hKey, BYTE * pbEncryptedData, ULONG ulEncryptedLen, BYTE * pbData, ULONG * pulDataLen)
	//��������	�����������ݵĽ��ܲ�������ָ��������Կ��ָ�����ݽ��н��ܣ������ܵ�����ֻ����һ�����飬���ܺ�����ı��浽ָ���Ļ������С�SKF_Decryptֻ�Ե����������ݽ��н��ܣ��ڵ���SKF_Decrypt֮ǰ���������SKF_DecryptInit��ʼ�����ܲ�����SKF_Decypt�ȼ����ȵ���SKF_DecryptUpdate�ٵ���SKF_DecryptFinal��
	//����		hKey 			[IN] ������Կ�����
	//			pbEncryptedData	[IN] ���������ݡ�
	//			ulEncryptedLen	[IN] ���������ݳ��ȡ�
	//			pbData			[OUT] ָ����ܺ�����ݻ�����ָ�룬��ΪNULLʱ�ɻ�ý��ܺ�����ݳ��ȡ�
	//			pulDataLen		[IN��OUT] ����ʱ��ʾ������ݻ��������ȣ����ʱ��ʾ�������ʵ�ʳ��ȡ�
	//����ֵ	SAR_OK��		�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_Decrypt(HANDLE hKey, BYTE * pbEncryptedData, ULONG ulEncryptedLen, BYTE * pbData, ULONG * pulDataLen);

	//7.6.32	�������ݽ���
	//����ԭ��	ULONG DEVAPI SKF_DecryptUpdate(HANDLE hKey, BYTE * pbEncryptedData, ULONG ulEncryptedLen, BYTE * pbData, ULONG * pulDataLen)
	//��������	����������ݵĽ��ܲ�������ָ��������Կ��ָ�����ݽ��н��ܣ������ܵ����ݰ���������飬���ܺ�����ı��浽ָ���Ļ������С�SKF_DecryptUpdate�Զ���������ݽ��н��ܣ��ڵ���SKF_DecryptUpdate֮ǰ���������SKF_DecryptInit��ʼ�����ܲ������ڵ���SKF_DecryptUpdate֮�󣬱������SKF_DecryptFinal�������ܲ�����
	//����		hKey 			[IN] ������Կ�����
	//			pbEncryptedData	[IN] ���������ݡ�
	//			ulEncryptedLen	[IN] ���������ݳ��ȡ�
	//			pbData			[OUT] ָ����ܺ�����ݻ�����ָ�롣
	//			pulDataLen		[IN��OUT] ����ʱ��ʾ������ݻ��������ȣ����ʱ��ʾ�������ʵ�ʳ��ȡ�
	//����ֵ	SAR_OK��		�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_DecryptUpdate(HANDLE hKey, BYTE * pbEncryptedData, ULONG ulEncryptedLen, BYTE * pbData, ULONG * pulDataLen);

	//7.6.33	��������
	//����ԭ��	ULONG DEVAPI SKF_DecryptFinal (HANDLE hKey, BYTE *pbDecryptedData, ULONG *pulDecryptedDataLen)
	//��������	��������������ݵĽ��ܡ��ȵ���SKF_DecryptInit��ʼ�����ܲ������ٵ���SKF_DecryptUpdate�Զ���������ݽ��н��ܣ�������SKF_DecryptFinal��������������ݵĽ��ܡ�
	//����		hKey				[IN] ������Կ�����
	//			pbDecryptedData		[OUT] ָ����ܽ���Ļ�����������˲���ΪNULLʱ����pulDecryptedDataLen���ؽ��ܽ���ĳ��ȡ�
	//			pulDecryptedDataLen	[IN��OUT] ����ʱ��ʾpbDecryptedData�������ĳ��ȣ����ʱ��ʾ���ܽ���ĳ��ȡ�
	//����ֵ	SAR_OK��			�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_DecryptFinal(HANDLE hKey, BYTE *pbDecryptedData, ULONG *pulDecryptedDataLen);

	//7.6.34	�����Ӵճ�ʼ��
	//����ԭ��	ULONG DEVAPI SKF_DigestInit(DEVHANDLE hDev, ULONG ulAlgID,  ECCPUBLICKEYBLOB *pPubKey, unsigned char *pucID, ULONG ulIDLen, HANDLE *phHash)
	//��������	��ʼ�������Ӵռ��������ָ�����������Ӵյ��㷨��
	//����		hDev	[IN] �����豸ʱ���ص��豸�����
	//			ulAlgID	[IN] �����Ӵ��㷨��ʶ��
	//			pPubKey	[IN] ǩ���߹�Կ����alAlgIDΪSGD_SM3ʱ��Ч��
	//			pucID	[IN] ǩ���ߵ�IDֵ����alAlgIDΪSGD_SM3ʱ��Ч��
	//			ulIDLen	[IN] ǩ����ID�ĳ��ȣ���alAlgIDΪSGD_SM3ʱ��Ч��
	//			phHash	[OUT] �����Ӵն�������
	//����ֵ	SAR_OK���ɹ���
	//������	�����롣
	//��ע		��ulAlgIDΪSGD_SM3��ulIDLen��Ϊ0�������pPubKey��pucID��Ч��ִ��SM2�㷨ǩ��Ԥ����1������
	//			���������ѭ����Կ���������ʩӦ�ü�����ϵ SM2�㷨����ʹ�ù淶����
	ULONG DEVAPI SKF_DigestInit(DEVHANDLE hDev, ULONG ulAlgID,  ECCPUBLICKEYBLOB *pPubKey, unsigned char *pucID, ULONG ulIDLen, HANDLE *phHash);

	//7.6.35	�������������Ӵ�
	//����ԭ��	ULONG DEVAPI SKF_Digest (HANDLE hHash, BYTE *pbData, ULONG ulDataLen, BYTE *pbHashData, ULONG *pulHashLen)
	//��������	�Ե�һ�������Ϣ���������Ӵռ��㡣����SKF_Digest֮ǰ���������SKF_DigestInit��ʼ�������Ӵռ��������
	//			SKF_Digest�ȼ��ڶ�ε���SKF_DigestUpdate֮���ٵ���SKF_DigestFinal��
	//����		hHash		[IN] �����Ӵն�������
	//			pbData		[IN] ָ����Ϣ���ݵĻ�������
	//			ulDataLen	[IN] ��Ϣ���ݵĳ��ȡ�
	//			pbHashData	[OUT] �����Ӵ����ݻ�����ָ�룬���˲���ΪNULLʱ����pulHashLen���������Ӵս���ĳ��ȡ�
	//			pulHashLen	[IN��OUT] ����ʱ��ʾ������ݻ��������ȣ����ʱ��ʾ�������ʵ�ʳ��ȡ�
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_Digest(HANDLE hHash, BYTE *pbData, ULONG ulDataLen, BYTE *pbHashData, ULONG *pulHashLen);

	//7.6.36	�������������Ӵ�
	//����ԭ��	ULONG DEVAPI SKF_DigestUpdate (HANDLE hHash, BYTE *pbData, ULONG  ulDataLen)
	//��������	�Զ���������Ϣ���������Ӵռ��㡣����SKF_DigestUpdate֮ǰ���������SKF_DigestInit��ʼ�������Ӵռ��������
	//			����SKF_DigestUpdate֮�󣬱������SKF_DigestFinal���������Ӵռ��������
	//����		hHash		[IN] �����Ӵն�������
	//			pbData		[IN] ָ����Ϣ���ݵĻ�������
	//			ulDataLen	[IN] ��Ϣ���ݵĳ��ȡ�
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_DigestUpdate(HANDLE hHash, BYTE *pbData, ULONG  ulDataLen);

	//7.6.37	���������Ӵ�
	//����ԭ��	ULONG DEVAPI SKF_DigestFinal (HANDLE hHash, BYTE *pHashData, ULONG  *pulHashLen)
	//��������	�������������Ϣ�������Ӵռ���������������Ӵս�����浽ָ���Ļ�������
	//����		hHash		[IN] �����Ӵն�������
	//			pHashData	[OUT] ���ص������Ӵս��������ָ�룬����˲���NULLʱ����pulHashLen�����Ӵս���ĳ��ȡ�
	//			pulHashLen	[IN��OUT] ����ʱ��ʾ�Ӵս���������ĳ��ȣ����ʱ��ʾ�����Ӵս���ĳ��ȡ�
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	//��ע		SKF_DigestFinal��������SKF_DigestUpdate֮��
	ULONG DEVAPI SKF_DigestFinal(HANDLE hHash, BYTE *pHashData, ULONG  *pulHashLen);

	//7.6.38	��Ϣ�����������ʼ��
	//����ԭ��	ULONG DEVAPI SKF_MacInit (HANDLE hKey, BLOCKCIPHERPARAM* pMacParam, HANDLE *phMac)
	//��������	��ʼ����Ϣ�����������������ü�����Ϣ������������������������Ϣ����������
	//����		hKey		[IN] ������Ϣ���������Կ�����
	//			pMacParam	[IN] ��Ϣ��֤������ز�����������ʼ��������ʼ�������ȡ���䷽���ȡ�
	//			phMac		[OUT] ��Ϣ�������������
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	//��ע		��Ϣ�����������÷�������㷨��CBCģʽ�������ܽ�������һ����Ϊ�����������������ݵĳ��ȱ����Ƿ�������㷨�鳤�ı������ӿ��ڲ�����������䡣
	ULONG DEVAPI SKF_MacInit(HANDLE hKey, BLOCKCIPHERPARAM* pMacParam, HANDLE *phMac);

	//7.6.39	����������Ϣ����������
	//����ԭ��	ULONG DEVAPI SKF_Mac(HANDLE hMac, BYTE* pbData, ULONG ulDataLen, BYTE *pbMacData, ULONG *pulMacLen)
	//��������	SKF_Mac���㵥һ�������ݵ���Ϣ�����롣
	//����		hMac		[IN] ��Ϣ����������
	//			pbData		[IN] ָ����������ݵĻ�������
	//			ulDataLen	[IN] ���������ݵĳ��ȡ�
	//			pbMacData	[OUT] ָ�������Mac���������˲���ΪNULLʱ����pulMacLen���ؼ����Mac����ĳ��ȡ�
	//			pulMacLen	[IN��OUT] ����ʱ��ʾpbMacData�������ĳ��ȣ����ʱ��ʾMac����ĳ��ȡ�
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	//��ע		����SKF_Mac֮ǰ���������SKF_MacInit��ʼ����Ϣ��������������SKF_Mac�ȼ��ڶ�ε���SKF_MacUpdate֮���ٵ���SKF_MacFinal��
	ULONG DEVAPI SKF_Mac(HANDLE hMac, BYTE* pbData, ULONG ulDataLen, BYTE *pbMacData, ULONG *pulMacLen);

	//7.6.40	����������Ϣ����������
	//����ԭ��	ULONG DEVAPI SKF_MacUpdate(HANDLE hMac, BYTE * pbData, ULONG ulDataLen)
	//��������	�������������ݵ���Ϣ�����롣
	//����		hMac		[IN] ��Ϣ����������
	//			pbData		[IN] ָ����������ݵĻ�������
	//			plDataLen	[IN] ���������ݵĳ��ȡ�
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	//��ע		����SKF_MacUpdate֮ǰ���������SKF_MacInit��ʼ����Ϣ������������������SKF_MacUpdate֮�󣬱������SKF_MacFinal��������������ݵ���Ϣ��������������
	ULONG DEVAPI SKF_MacUpdate(HANDLE hMac, BYTE * pbData, ULONG ulDataLen);

	//7.6.41	������Ϣ����������
	//����ԭ��	ULONG DEVAPI SKF_MacFinal (HANDLE hMac, BYTE *pbMacData, ULONG *pulMacDataLen)
	//��������	��������������ݵ���Ϣ��������������
	//����		hMac			[IN] ��Ϣ����������
	//			pbMacData		[OUT] ָ����Ϣ������Ļ����������˲���ΪNULLʱ����pulMacDataLen������Ϣ�����뷵�صĳ��ȡ�
	//			pulMacDataLen	[OUT] ����ʱ��ʾ��Ϣ�����뻺��������󳤶ȣ�������Ϣ������ĳ��ȡ�
	//����ֵ	SAR_OK��		�ɹ���
	//������	�����롣
	//��ע		SKF_MacFinal��������SKF_MacUpdate֮��
	ULONG DEVAPI SKF_MacFinal(HANDLE hMac, BYTE *pbMacData, ULONG *pulMacDataLen);

	//7.6.42	�ر����������
	//����ԭ��	ULONG DEVAPI SKF_CloseHandle(HANDLE hHandle)
	//��������	�رջỰ��Կ�������Ӵն�����Ϣ���������ECC��ԿЭ�̵Ⱦ����
	//����		hHandle		[IN] Ҫ�رյĶ�������
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_CloseHandle(HANDLE hHandle);


	// ��չ����

	// ECC����
	//����ԭ��	ULONG DEVAPI SKF_ECCDecrypt(HCONTAINER hContainer, BYTE *pbCiphertext, ULONG ulCiphertextLen, BYTE *pbPlaintext, ULONG *pulPlaintextLen)
	//��������	ECC���ݽ��ܡ��������н���˽Կ�������ݣ����ܺ�Ľ����ŵ�pbPlaintext�С�
	//����		hContainer		[IN] ��Կ���������
	//			pbCiphertext	[IN] �����ܵ����ݡ��˲���ΪECCCIPHERBLOB�������ݡ�
	//			ulCiphertextLen	[IN] ���������ݳ��ȡ�
	//			pbPlaintext		[OUT] ���ܺ�����ģ�����ò���ΪNULL������pulPlaintextLen��������Ҫ���ڴ�ռ��С��
	//			pulPlaintextLen	[IN OUT] ����ʱ��ʾpbPlaintext�������ĳ��ȣ����ʱ��ʾ���Ľ���ĳ��ȡ�
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_ECCDecrypt(HCONTAINER hContainer, BYTE *pbCiphertext, ULONG ulCiphertextLen, BYTE *pbPlaintext, ULONG *pulPlaintextLen);

	// ECC����2
	//����ԭ��	ULONG DEVAPI SKF_ECCDecryptEx(HCONTAINER hContainer, PECCCIPHERBLOB pCipherText, BYTE *pbPlaintext, ULONG *pulPlaintextLen)
	//��������	ECC���ݽ��ܡ��������н���˽Կ�������ݣ����ܺ�Ľ����ŵ�pbPlaintext�С�
	//����		hContainer		[IN] ��Կ���������
	//			pCipherText		[IN] �����ܵ����ݡ��˲���ΪECCCIPHERBLOB�������ݡ�
	//			pbPlaintext		[OUT] ���ܺ�����ģ�����ò���ΪNULL������pulPlaintextLen��������Ҫ���ڴ�ռ��С��
	//			pulPlaintextLen	[IN OUT] ����ʱ��ʾpbPlaintext�������ĳ��ȣ����ʱ��ʾ���Ľ���ĳ��ȡ�
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_ECCDecryptEx(HCONTAINER hContainer, PECCCIPHERBLOB pCipherText, BYTE *pbPlaintext, ULONG *pulPlaintextLen);


	// RSA����
	//����ԭ��	ULONG DEVAPI SKF_RSAPriKeyOperation(HCONTAINER hContainer, BYTE *pbIn, ULONG ulInLen, BYTE *pbOut, ULONG *pulOutLen, BOOL bSignFlag)
	//����		hContainer		[IN] ��Կ���������
	//			pbIn			[IN] �������ݡ�
	//			ulInLen			[IN] �������ݳ��ȡ�
	//			pbOut			[OUT] ������ݡ�
	//			pulOutLen		[IN OUT] ����ʱ��ʾpbOut�������ĳ��ȣ����ʱ��ʾ���Ľ���ĳ��ȡ�
	//			bSignFlag       [IN] ��0����ʾʹ��ǩ����Կ�ԣ�0����ʾ������Կ��
	ULONG DEVAPI SKF_RSAPriKeyOperation(HCONTAINER hContainer, BYTE *pbIn, ULONG ulInLen, BYTE *pbOut, ULONG *pulOutLen, BOOL bSignFlag);


	// ��ȡӦ�ð�ȫ״̬
	//����ԭ��	ULONG DEVAPI SKF_GetSecureState (HAPPLICATION hApplication, ULONG *pulSecureState)
	//��������	��ȡӦ�õ�ǰ�İ�ȫ״̬��
	//����		hApplication	[IN] Ӧ�þ����
	//����		pulSecureState	[OUT] Ӧ�õ�ǰ��ȫ״̬��
	//����ֵ	SAR_OK��	�ɹ���
	//������	�����롣
	ULONG DEVAPI SKF_GetSecureState(HAPPLICATION hApplication, ULONG *pulSecureState);

	//7.6.20	ECC������ԿЭ�̲��������: ��ʱ��Կ�ԣ�ʹ�ù̶�ֵ
	ULONG DEVAPI SKF_GenerateAgreementDataWithECCEx(HCONTAINER hContainer, ULONG ulAlgId,ECCPUBLICKEYBLOB*  pTempECCPubKeyBlob,BYTE* pbID, ULONG ulIDLen,HANDLE *phAgreementHandle);

	//7.6.21 ECC����Э�����ݲ�����Ự��Կ ��չ�ӿ�: ʹ�ù̶���ʱ��Կ��, ����Э�̺����Կ
	ULONG DEVAPI SKF_GenerateAgreementDataAndKeyWithECCEx(HANDLE hContainer, ULONG ulAlgId,
		ECCPUBLICKEYBLOB*  pSponsorECCPubKeyBlob, ECCPUBLICKEYBLOB*  pSponsorTempECCPubKeyBlob,
		ECCPUBLICKEYBLOB*  pTempECCPubKeyBlob,
		BYTE* pbID, ULONG ulIDLen, BYTE *pbSponsorID, ULONG ulSponsorIDLen,
		BYTE *pbAgreementKey,
		ULONG *pulAgreementKeyLen);

	//7.6.21 ECC����Э�����ݲ�����Ự��Կ ��չ�ӿ�: ����B����ʱ��Կ��, ����Э�̺����Կ
	ULONG DEVAPI SKF_GenerateAgreementDataAndKeyWithECCEx2(HANDLE hContainer, ULONG ulAlgId,
		ECCPUBLICKEYBLOB*  pSponsorECCPubKeyBlob, ECCPUBLICKEYBLOB*  pSponsorTempECCPubKeyBlob,
		BYTE*  pbTempECCPair, // ���ݸ�ʽ��PubX(32�ֽ�) + PubY(32�ֽ�) + Pri(32�ֽ�)
		BYTE* pbID, ULONG ulIDLen, BYTE *pbSponsorID, ULONG ulSponsorIDLen,
		BYTE *pbAgreementKey,
		ULONG *pulAgreementKeyLen);

	//7.6.22 ECC����Ự��Կ ��չ�ӿ�: ����Э�̺����Կ
	ULONG DEVAPI SKF_GenerateKeyWithECCEx(HANDLE hAgreementHandle,
		ECCPUBLICKEYBLOB*  pECCPubKeyBlob,
		ECCPUBLICKEYBLOB*  pTempECCPubKeyBlob,
		BYTE* pbID, ULONG ulIDLen, 
		BYTE *pbAgreementKey, ULONG *pulAgreementKeyLen);



	ULONG DEVAPI SKF_ExtGenECCKeyPair(DEVHANDLE hDev, ULONG ulBitsLen, PECCPUBLICKEYBLOB pECCPublicKeyBlob, PECCPRIVATEKEYBLOB pECCPrivateKeyBlob);

	ULONG DEVAPI SKF_ImportECCExchangeKeyPair(HCONTAINER hContainer, PENVELOPEDKEYBLOB pEnvelopedKeyBlob);
	ULONG DEVAPI SKF_ImportExchangeCertificate(HCONTAINER hContainer, BYTE* pbCert, ULONG ulCertLen);
	ULONG DEVAPI SKF_ExportECCExchangePubKey(HCONTAINER hContainer, PECCPUBLICKEYBLOB pECCPublicKeyBlob);

	ULONG DEVAPI SKF_ImportHMACKey(HAPPLICATION hApplication, BYTE* pbLabel, ULONG ulLabelLen, BYTE* pbID, ULONG ulIDLen, BYTE* pbKey, ULONG ulKeyLen);



	// ����ECC������Կ��
	ULONG DEVAPI SKF_GenECCEncryptKeyPair(HCONTAINER hContainer, ULONG ulAlgId, ECCPUBLICKEYBLOB *pBlob);
	ULONG DEVAPI SKF_ImportECCSignKeyPair(HCONTAINER hContainer, PENVELOPEDKEYBLOB pEnvelopedKeyBlob);

	ULONG DEVAPI SKF_GenSessionKey(HCONTAINER hContainer, ULONG ulAlgID, HANDLE* phKey);
	ULONG DEVAPI SKF_WrapKey(HCONTAINER hContainer, HANDLE hKey, ECCPUBLICKEYBLOB *pBlob, ECCCIPHERBLOB *pEccCipherBlob);
	ULONG DEVAPI SKF_UnwrapKey(HCONTAINER hContainer, ECCCIPHERBLOB *pEccCipherBlob, ULONG ulAlgID, HANDLE* phKey);


#ifdef __cplusplus
}
#endif

#endif	//__SKFINTERFACE_H
