#ifndef _O_ALL_TYPE_DEF_H
#define _O_ALL_TYPE_DEF_H

#include "common.h"

#define EXT_COPY_NONE		0
#define EXT_COPY_ADD		1
#define EXT_COPY_ALL		2

// ���֧���豸����
#define MAX_DEV_NUM	16
#define MAX_CON_NUM 1024    // ÿ���豸�����������

// SM2˽Կ����
#define SM2_BYTES_LEN 32
#define SM2_BITS_LEN 256
#define RSA_2048_DATA_LEN 256
#define RSA_1024_DATA_LEN 128
#define RSA_2048_BITS_LEN 2048
#define RSA_1024_BITS_LEN 1024
#define READ_DATA_LEN 1024
#define SM3_DIGEST_LEN 32
#define MAX_CON_NAME_LEN 20
#define MAXUINT32 ((UINT32)~((UINT32)0))
#define CHAR_TO_16(achar) ((achar)>='0'&&(achar)<='9'?((achar)-'0'):((((((achar)>='A'  )&&( (achar)<='Z' )  ))? ((achar)-'A'): ((achar)-'a')) + 10))


////////////////////////////////////////////////////////////////////////////
// Copy from skf define
#define ECC_MAX_XCOORDINATE_BITS_LEN 512	//ECC�㷨X�������󳤶�
#define ECC_MAX_YCOORDINATE_BITS_LEN 512	//ECC�㷨Y�������󳤶�
////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////
// Copy from pci define
/*ECC��Կ*/
#define ECCref_MAX_BITS			256 
#define ECCref_MAX_LEN			((ECCref_MAX_BITS+7) / 8)
#define ECCref_MAX_CIPHER_LEN	136
////////////////////////////////////////////////////////////////////////////

typedef void * OPT_HCONTAINER;
typedef void * OPT_HDEVICE;

typedef char             OPT_Char;
typedef unsigned char    OPT_UChar;
typedef unsigned char    OPT_Byte;
typedef unsigned short   OPT_Word;
typedef unsigned int     OPT_Dword;
#if 0
typedef unsigned __int64 OPT_Qword;
#endif

typedef char             OPT_Int8;
typedef short            OPT_Int16;
typedef int              OPT_Int32;
#if 0
typedef __int64          OPT_Int64;
#endif

typedef unsigned char    OPT_UInt8;
typedef unsigned short   OPT_UInt16;
typedef unsigned int     OPT_UInt32;
#if 0
typedef unsigned __int64 OPT_UInt64;
#endif

typedef long             OPT_Long;
typedef unsigned long    OPT_ULong;

typedef void*            OPT_Handle;

#ifdef __cplusplus
extern "C" {
#endif
	typedef enum _OPE_ERR_
	{
		OPE_ERR_OK							=	0x00000000,						// ��ȷ

		OPE_ERR_BASE						=	0x1FF10000,

		/////////////////////// Common ERR
		OPE_ERR_INVALID_PARAM				=	(OPE_ERR_BASE+0x00000001)	,	// ��������
		OPE_ERR_NOT_ENOUGH_MEMORY			=	(OPE_ERR_BASE+0x00000002)	,	// �����ڴ治��
		OPE_ERR_BUFF_SMALL					=	(OPE_ERR_BASE+0x00000003)	,	// �û������Buffer̫С

		/////////////////////// PKCS11 ERR
		OPE_ERR_LIB_NOT_INITED				=	(OPE_ERR_BASE+0x00000101)	,	// �ӿڿ�δ��ʼ��
		OPE_ERR_NO_DEV						=	(OPE_ERR_BASE+0x00000102)	,	// δ���ֿ��豸
		OPE_ERR_CONNECT_STATE				=	(OPE_ERR_BASE+0x00000103)	,	// �豸����״̬ʧЧ,��Ҫ����Initialize(��ʼ��)
		OPE_ERR_NOT_LOGGED_IN				=	(OPE_ERR_BASE+0x00000104)	,	// �û�δ��¼
		OPE_ERR_NO_CERT						=	(OPE_ERR_BASE+0x00000105)	,	// ��֤��
		OPE_ERR_NO_PRIVKEY					=	(OPE_ERR_BASE+0x00000106)	,	// ��˽Կ
		OPE_ERR_INVALID_KEYLEN				=	(OPE_ERR_BASE+0x00000107)	,	// ��Կ���ȴ���
		OPE_ERR_NO_SUPPORT_RSA_MODULUS		=	(OPE_ERR_BASE+0x00000108)	,	// RSA��Կ���Ȳ�֧��(��1024���2048����Կ)
		OPE_ERR_CONNECT_DEV					=   (OPE_ERR_BASE+0x00000109)	,	// �����豸����
		OPE_ERR_OPEN_APPLICATION			=   (OPE_ERR_BASE+0x0000010A)	,   // ��Ӧ�ó���
		OPE_ERR_INITIALIZE_P11				=   (OPE_ERR_BASE+0x0000010B)	,   // ��ʼ��P11����
		OPE_ERR_FINALIZE_P11				=   (OPE_ERR_BASE+0x0000010C)	,   // ж��P11����
		OPE_ERR_DEV_MEM_NOT_ENOUGH			=   (OPE_ERR_BASE+0x0000010D)	,	// �豸�ڴ治��
		OPE_ERR_NO_CONTAINER				=   (OPE_ERR_BASE+0x0000010F)	,   // ����������
		OPE_ERR_DEV_NUMBER_ERR				=   (OPE_ERR_BASE+0x00000110)	,   // �豸��������ȷ
		OPE_ERR_DEV_NUMBER_ZERO             =   (OPE_ERR_BASE+0x00000111)   ,   // δ�����豸

		///////////////////// OpenSSL ERR
		OPE_ERR_VERIFY_CSR					=   (OPE_ERR_BASE+0x00000201)	,   // ��֤ʧ��
		OPE_ERR_INITIALIZE_OPENSSL			=   (OPE_ERR_BASE+0x00000202)	,   // ��ʼ��P11����
		OPE_ERR_FINALIZE_OPENSSL			=   (OPE_ERR_BASE+0x00000203)	,   // ж��P11����

		//////////////////// PCI ERR
		OPE_ERR_PCI_NOT_INIT				=   (OPE_ERR_BASE+0x00000301)	,  // δ��ʼ��
		OPE_ERR_PCI_CHECK_ROOTSM2KEY_EXIST  =   (OPE_ERR_BASE+0x00000302), //��Կ����
		OPE_ERR_PCI_CHECK_ROOTSM2KEY_NOT_EXIST=	(OPE_ERR_BASE+0x00000303),


		OPE_ERR_UNKNOWN						=	(OPE_ERR_BASE+0x00000FFF)	,	// δ֪����


		PCI_PARAM_ERR = 0x0F000001,
		PCI_CARD_NO_FIND_IC = 0x0F000006,	// δ�ҵ�IC��
		PCI_CARD_INSERT_ERR = 0x0F000007,// IC���뷽�����򲻵�λ
		PCI_CARD_RIGHT_ERR = 0x0F000008,	// ����Ȩ�޲�����
		PCI_CARD_IC_PIN_ERR = 0x0F000009,	// IC���������
		PCI_CARD_IC_PIN_LOCK_ERR = 0x0F00000A,// IC��������	


		/*��׼�����붨��*/
		PCI_SDR_BASE = 0x01000000,
		PCI_SDR_UNKNOWERR = (PCI_SDR_BASE + 0x00000001),	   /*δ֪����*/
		PCI_SDR_NOTSUPPORT = (PCI_SDR_BASE + 0x00000002),	   /*��֧��*/
		PCI_SDR_COMMFAIL = (PCI_SDR_BASE + 0x00000003),    /*ͨ�Ŵ���*/
		PCI_SDR_HARDFAIL = (PCI_SDR_BASE + 0x00000004),    /*Ӳ������*/
		PCI_SDR_OPENDEVICE = (PCI_SDR_BASE + 0x00000005),    /*���豸����*/
		PCI_SDR_OPENSESSION = (PCI_SDR_BASE + 0x00000006),    /*�򿪻Ự�������*/
		PCI_SDR_PARDENY = (PCI_SDR_BASE + 0x00000007),    /*Ȩ�޲�����*/
		PCI_SDR_KEYNOTEXIST = (PCI_SDR_BASE + 0x00000008),    /*��Կ������*/
		PCI_SDR_ALGNOTSUPPORT = (PCI_SDR_BASE + 0x00000009),    /*��֧�ֵ��㷨*/
		PCI_SDR_ALGMODNOTSUPPORT = (PCI_SDR_BASE + 0x0000000A),    /*��֧�ֵ��㷨ģʽ*/
		PCI_SDR_PKOPERR = (PCI_SDR_BASE + 0x0000000B),    /*��Կ�������*/
		PCI_SDR_SKOPERR = (PCI_SDR_BASE + 0x0000000C),    /*˽Կ�������*/
		PCI_SDR_SIGNERR = (PCI_SDR_BASE + 0x0000000D),    /*ǩ������*/
		PCI_SDR_VERIFYERR = (PCI_SDR_BASE + 0x0000000E),    /*��֤����*/
		PCI_SDR_SYMOPERR = (PCI_SDR_BASE + 0x0000000F),    /*�Գ��������*/
		PCI_SDR_STEPERR = (PCI_SDR_BASE + 0x00000010),    /*�������*/
		PCI_SDR_FILESIZEERR = (PCI_SDR_BASE + 0x00000011),    /*�ļ���С������������ݳ��ȷǷ�*/
		PCI_SDR_FILENOEXIST = (PCI_SDR_BASE + 0x00000012),    /*�ļ�������*/
		PCI_SDR_FILEOFSERR = (PCI_SDR_BASE + 0x00000013),    /*�ļ�����ƫ��������*/
		PCI_SDR_KEYTYPEERR = (PCI_SDR_BASE + 0x00000014),    /*��Կ���ʹ���*/
		PCI_SDR_KEYERR = (PCI_SDR_BASE + 0x00000015),    /*��Կ����*/

		/*============================================================*/
		/*��չ������*/
		PCI_SWR_BASE = (PCI_SDR_BASE + 0x00010000),	/*�Զ�����������ֵ*/
		PCI_SWR_INVALID_USER = (PCI_SWR_BASE + 0x00000001),	/*��Ч���û���*/
		PCI_SWR_INVALID_AUTHENCODE = (PCI_SWR_BASE + 0x00000002),	/*��Ч����Ȩ��*/
		PCI_SWR_PROTOCOL_VER_ERR = (PCI_SWR_BASE + 0x00000003),	/*��֧�ֵ�Э��汾*/
		PCI_SWR_INVALID_COMMAND = (PCI_SWR_BASE + 0x00000004),	/*�����������*/
		PCI_SWR_INVALID_PARAMETERS = (PCI_SWR_BASE + 0x00000005),	/*����������������ݰ���ʽ*/
		PCI_SWR_FILE_ALREADY_EXIST = (PCI_SWR_BASE + 0x00000006),	/*�Ѵ���ͬ���ļ�*/
		PCI_SWR_SYNCH_ERR = (PCI_SWR_BASE + 0x00000007),	/*�࿨ͬ������*/
		PCI_SWR_SYNCH_LOGIN_ERR = (PCI_SWR_BASE + 0x00000008),	/*�࿨ͬ�����¼����*/

		PCI_SWR_SOCKET_TIMEOUT = (PCI_SWR_BASE + 0x00000100),	/*��ʱ����*/
		PCI_SWR_CONNECT_ERR = (PCI_SWR_BASE + 0x00000101),	/*���ӷ���������*/
		PCI_SWR_SET_SOCKOPT_ERR = (PCI_SWR_BASE + 0x00000102),	/*����Socket��������*/
		PCI_SWR_SOCKET_SEND_ERR = (PCI_SWR_BASE + 0x00000104),	/*����LOGINRequest����*/
		PCI_SWR_SOCKET_RECV_ERR = (PCI_SWR_BASE + 0x00000105),	/*����LOGINRequest����*/
		PCI_SWR_SOCKET_RECV_0 = (PCI_SWR_BASE + 0x00000106),	/*����LOGINRequest����*/

		PCI_SWR_SEM_TIMEOUT = (PCI_SWR_BASE + 0x00000200),	/*��ʱ����*/
		PCI_SWR_NO_AVAILABLE_HSM = (PCI_SWR_BASE + 0x00000201),	/*û�п��õļ��ܻ�*/
		PCI_SWR_NO_AVAILABLE_CSM = (PCI_SWR_BASE + 0x00000202),	/*���ܻ���û�п��õļ���ģ��*/

		PCI_SWR_CONFIG_ERR = (PCI_SWR_BASE + 0x00000301),	/*�����ļ�����*/

		/*============================================================*/
		/*���뿨������*/
		PCI_SWR_CARD_BASE = (PCI_SDR_BASE + 0x00020000),			/*���뿨������*/
		PCI_SWR_CARD_UNKNOWERR = (PCI_SWR_CARD_BASE + 0x00000001),	//δ֪����
		PCI_SWR_CARD_NOTSUPPORT = (PCI_SWR_CARD_BASE + 0x00000002),	//��֧�ֵĽӿڵ���
		PCI_SWR_CARD_COMMFAIL = (PCI_SWR_CARD_BASE + 0x00000003),	//���豸ͨ��ʧ��
		PCI_SWR_CARD_HARDFAIL = (PCI_SWR_CARD_BASE + 0x00000004),	//����ģ������Ӧ
		PCI_SWR_CARD_OPENDEVICE = (PCI_SWR_CARD_BASE + 0x00000005),	//���豸ʧ��
		PCI_SWR_CARD_OPENSESSION = (PCI_SWR_CARD_BASE + 0x00000006),	//�����Ựʧ��
		PCI_SWR_CARD_PARDENY = (PCI_SWR_CARD_BASE + 0x00000007),	//��˽Կʹ��Ȩ��
		PCI_SWR_CARD_KEYNOTEXIST = (PCI_SWR_CARD_BASE + 0x00000008),	//�����ڵ���Կ����
		PCI_SWR_CARD_ALGNOTSUPPORT = (PCI_SWR_CARD_BASE + 0x00000009),	//��֧�ֵ��㷨����
		PCI_SWR_CARD_ALGMODNOTSUPPORT = (PCI_SWR_CARD_BASE + 0x00000010),	//��֧�ֵ��㷨����
		PCI_SWR_CARD_PKOPERR = (PCI_SWR_CARD_BASE + 0x00000011),	//��Կ����ʧ��
		PCI_SWR_CARD_SKOPERR = (PCI_SWR_CARD_BASE + 0x00000012),	//˽Կ����ʧ��
		PCI_SWR_CARD_SIGNERR = (PCI_SWR_CARD_BASE + 0x00000013),	//ǩ������ʧ��
		PCI_SWR_CARD_VERIFYERR = (PCI_SWR_CARD_BASE + 0x00000014),	//��֤ǩ��ʧ��
		PCI_SWR_CARD_SYMOPERR = (PCI_SWR_CARD_BASE + 0x00000015),	//�Գ��㷨����ʧ��
		PCI_SWR_CARD_STEPERR = (PCI_SWR_CARD_BASE + 0x00000016),	//�ಽ���㲽�����
		PCI_SWR_CARD_FILESIZEERR = (PCI_SWR_CARD_BASE + 0x00000017),	//�ļ����ȳ�������
		PCI_SWR_CARD_FILENOEXIST = (PCI_SWR_CARD_BASE + 0x00000018),	//ָ�����ļ�������
		PCI_SWR_CARD_FILEOFSERR = (PCI_SWR_CARD_BASE + 0x00000019),	//�ļ���ʼλ�ô���
		PCI_SWR_CARD_KEYTYPEERR = (PCI_SWR_CARD_BASE + 0x00000020),	//��Կ���ʹ���
		PCI_SWR_CARD_KEYERR = (PCI_SWR_CARD_BASE + 0x00000021),	//��Կ����
		PCI_SWR_CARD_BUFFER_TOO_SMALL = (PCI_SWR_CARD_BASE + 0x00000101),	//���ղ����Ļ�����̫С
		PCI_SWR_CARD_DATA_PAD = (PCI_SWR_CARD_BASE + 0x00000102),	//����û�а���ȷ��ʽ��䣬����ܵõ����������ݲ���������ʽ
		PCI_SWR_CARD_DATA_SIZE = (PCI_SWR_CARD_BASE + 0x00000103),	//���Ļ����ĳ��Ȳ�������Ӧ���㷨Ҫ��
		PCI_SWR_CARD_CRYPTO_NOT_INIT = (PCI_SWR_CARD_BASE + 0x00000104),	//�ô������û��Ϊ��Ӧ���㷨���ó�ʼ������

		//01/03/09�����뿨Ȩ�޹��������
		PCI_SWR_CARD_MANAGEMENT_DENY = (PCI_SWR_CARD_BASE + 0x00001001),	//����Ȩ�޲�����
		PCI_SWR_CARD_OPERATION_DENY = (PCI_SWR_CARD_BASE + 0x00001002),	//����Ȩ�޲�����
		PCI_SWR_CARD_DEVICE_STATUS_ERR = (PCI_SWR_CARD_BASE + 0x00001003),	//��ǰ�豸״̬���������в���
		PCI_SWR_CARD_LOGIN_ERR = (PCI_SWR_CARD_BASE + 0x00001011),	//��¼ʧ��
		PCI_SWR_CARD_USERID_ERR = (PCI_SWR_CARD_BASE + 0x00001012),	//�û�ID��Ŀ/�������
		PCI_SWR_CARD_PARAMENT_ERR = (PCI_SWR_CARD_BASE + 0x00001013),	//��������

		//05/06�����뿨Ȩ�޹��������
		PCI_SWR_CARD_MANAGEMENT_DENY_05 = (PCI_SWR_CARD_BASE + 0x00000801),	//����Ȩ�޲�����
		PCI_SWR_CARD_OPERATION_DENY_05 = (PCI_SWR_CARD_BASE + 0x00000802),	//����Ȩ�޲�����
		PCI_SWR_CARD_DEVICE_STATUS_ERR_05 = (PCI_SWR_CARD_BASE + 0x00000803),	//��ǰ�豸״̬���������в���
		PCI_SWR_CARD_LOGIN_ERR_05 = (PCI_SWR_CARD_BASE + 0x00000811),	//��¼ʧ��
		PCI_SWR_CARD_USERID_ERR_05 = (PCI_SWR_CARD_BASE + 0x00000812),	//�û�ID��Ŀ/�������
		PCI_SWR_CARD_PARAMENT_ERR_05 = (PCI_SWR_CARD_BASE + 0x00000813),	//��������

		/*============================================================*/
		/*����������*/
		PCI_SWR_CARD_READER_BASE = (PCI_SDR_BASE + 0x00030000),	//	���������ʹ���
		PCI_SWR_CARD_READER_PIN_ERROR = (PCI_SWR_CARD_READER_BASE + 0x000063CE),  //�������
		PCI_SWR_CARD_READER_NO_CARD = (PCI_SWR_CARD_READER_BASE + 0x0000FF01),	 //	ICδ����
		PCI_SWR_CARD_READER_CARD_INSERT = (PCI_SWR_CARD_READER_BASE + 0x0000FF02),	 //	IC���뷽�����򲻵�λ
		PCI_SWR_CARD_READER_CARD_INSERT_TYPE = (PCI_SWR_CARD_READER_BASE + 0x0000FF03),	 //	IC���ʹ���

	}OPE_ERR;

	// ��Կ����
	typedef enum _OPE_KEY_TYPE { 
		OPE_KEY_TYPE_SM2, OPE_KEY_TYPE_RSA, OPE_KEY_TYPE_EC,
	} OPE_KEY_TYPE;


	typedef enum _OPE_CON_TYPE
	{
		OPE_CON_TYPE_SIGN =0,OPE_CON_TYPE_ENCYPT = 1,
	}OPE_CON_TYPE;
	
	typedef enum _OPE_ENCODE_TYPE { 
		OPE_ENCODE_TYPE_DER = 0,	   	// �ļ���������: DER
		OPE_ENCODE_TYPE_PEM,			// �ļ���������: PEM
	} OPE_ENCODE_TYPE;

	// �û�������Ϣ
	typedef struct _OPST_USERINFO
	{
		char countryName[32];
		unsigned int uiLenC;
		char stateOrProvinceName[32];
		unsigned int uiLenST;
		char localityName[128];
		unsigned int uiLenL;
		char organizationName[128];
		unsigned int uiLenO;
		char organizationalUnitName[128];
		unsigned int uiLenOU;
		char commonName[128];
		unsigned int uiLenCN;
		char emailAddress[128];
		unsigned int uiLenEA;
		char challengePassword[64];
		unsigned int uiLenCP;
		char unstructuredName[128];
		unsigned int uiLenUN;
		char idCardNumber[32];
		unsigned int uiLenID;
	}OPST_USERINFO;

	typedef struct _OPST_CRL
	{
		unsigned char sn[128];		// ���к�
		unsigned char snlen;
		unsigned int reason_code;	// ԭ��
		unsigned long dt;				// ����ʱ��
	}OPST_CRL;

	typedef struct _OPST_HANDLE_NODE
	{
		void * ptr_data;
		struct _OPST_HANDLE_NODE * ptr_next;
	}OPST_HANDLE_NODE;

	// == CK_SLOT_INFO(PKCS11)
	typedef struct _OPST_CK_VERSION {
		unsigned char       major;  /* integer portion of version number */
		unsigned char       minor;  /* 1/100ths portion of version number */
	} OPST_CK_VERSION;

	// == CK_SLOT_INFO(PKCS11)
	typedef struct _OPST_CK_SLOT_INFO {
		/* slotDescription and manufacturerID have been changed from
		* CK_CHAR to CK_UTF8CHAR for v2.10 */
		unsigned char   slotDescription[64];  /* blank padded */
		unsigned char   manufacturerID[32];   /* blank padded */
		unsigned int      flags;

		/* hardwareVersion and firmwareVersion are new for v2.0 */
		OPST_CK_VERSION    hardwareVersion;  /* version of hardware */
		OPST_CK_VERSION    firmwareVersion;  /* version of firmware */
	} OPST_CK_SLOT_INFO;

	// �豸
	typedef struct _OPST_DEV
	{
		unsigned int	uiSlotID;
		unsigned int	hSession;
		// �û��Ƿ��ѵ�¼
		unsigned char		bLoginState;
		// Ӳ����Ϣ
		OPST_CK_SLOT_INFO	slotInfo;
	} OPST_DEV;

	// ����
	typedef struct _OPST_CONTAINER
	{
		// ���������� + ��������  ���� ������Ϊ1234  ����Ϊ1234+0 ǩ��Ϊ1234+1
		char szName[MAX_CON_NAME_LEN + 1];
		// ���������� + 1(���ͳ���)
		int uiLen;
		OPST_DEV * ptr_dev;
	}OPST_CONTAINER;

	typedef struct _OPST_CERT_INFO
	{
		char common_name[32];
		int common_name_len;
		char subject[128];
		int subject_len;
		char issuer[128];
		int issuer_len;
		char sn[128];
		int sn_len;
		int not_before;
		int not_after;
		int key_usage;
		int key_type;
		int verify;
		char public_key_value[128];
		int public_key_len;
	}OPST_CERT_INFO;


	// USBʹ������
	typedef enum _OPE_USB_META_USE_TYPE
	{
		OPE_USB_META_USE_TYPE_AUTH = 0 , //��֤��¼KEY
		OPE_USB_META_USE_TYPE_CERT = 1 , //֤��KEY
	}OPE_USB_META_USE_TYPE;

	// USBʹ������
	typedef enum _OPE_USB_TARGET
	{
		OPE_USB_TARGET_SELF = 0 ,  //��ǰKEY
		OPE_USB_TARGET_OTHER = 1 , //�ǵ�ǰKEY
	}OPE_USB_TARGET;

	// USB��������
	typedef enum _OPE_USB_META_MAN_TYPE
	{
		OPE_USB_META_MAN_TYPE_ADMIN   = 1,
		OPE_USB_META_MAN_TYPE_OP      = 2,
		OPE_USB_META_MAN_TYPE_AUDIT   = 3,
	}OPE_USB_META_MAN_TYPE;

	typedef struct _OPT_ST_USB_META
	{
		unsigned int uiUSBMetaUseType;  // USBʹ������ OPE_USB_META_USE_TYPE
		unsigned int uiUSBMetaManType;  // USB�������� OPE_USB_META_MAN_TYPE
		char szName[256];
		// other META
	}OPT_ST_USB_META;

	enum EINPUT_DATA_TYPE{
		E_INPUT_DATA_TYPE_PRIVATEKEY,
		E_INPUT_DATA_TYPE_PUBLICKEY,
		E_INPUT_DATA_TYPE_CERT
	};

	enum EFILEENCODE_TYPE{
		EFILEENCODE_TYPE_DER,
		EFILEENCODE_TYPE_PEM
	};

	// == PCI ECCrefPublicKey_st
	typedef struct _OPST_PCI_ECCrefPublicKey_st
	{
		unsigned int  bits;
		unsigned char x[ECCref_MAX_LEN]; 
		unsigned char y[ECCref_MAX_LEN]; 
	} OPST_PCI_ECCrefPublicKey;

	// == PCI ECCrefPrivateKey_st
	typedef struct _OPST_PCI_ECCrefPrivateKey_st
	{
		unsigned int  bits;
		unsigned char D[ECCref_MAX_LEN];
	} OPST_PCI_ECCrefPrivateKey;


	// == SKF ECCPUBLICKEYBLOB
	typedef struct _OPST_SKF_ECCPUBLICKEYBLOB{
		OPT_UInt32	BitLen;											//ģ����ʵ��λ����	������8�ı���
		OPT_Byte	XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8];	//�����ϵ��X����	�������ϵ�����
		OPT_Byte	YCoordinate[ECC_MAX_YCOORDINATE_BITS_LEN/8];	//�����ϵ��Y����	�������ϵ�����
	}OPST_SKF_ECCPUBLICKEYBLOB;

	// == SKF ECCCIPHERBLOB
	typedef struct _OPST_SKF_ECCCIPHERBLOB{
		OPT_Byte  XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8];		//��y�����Բ�����ϵĵ㣨x��y��
		OPT_Byte  YCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8];		//��x�����Բ�����ϵĵ㣨x��y��
		OPT_Byte  HASH[32];											//���ĵ��Ӵ�ֵ
		OPT_UInt32	CipherLen;										//�������ݳ���
		OPT_Byte  Cipher[SM2_BYTES_LEN];							//��������	ʵ�ʳ���ΪCipherLen			
	} OPST_SKF_ECCCIPHERBLOB;

	
	// == SKF_ENVELOPEDKEYBLOB(SKF)
	typedef struct _OPST_SKF_ENVELOPEDKEYBLOB{
		OPT_UInt32 Version;							// ��ǰ�汾Ϊ 1
		OPT_UInt32 uiSymmAlgID;						// �Գ��㷨��ʶ���޶�ECBģʽ
		OPT_UInt32 uiBits;							// ������Կ�Ե���Կλ����
		OPT_Byte cbEncryptedPriKey[64];			// �Գ��㷨���ܵļ���˽Կ,����˽Կ��ԭ��ΪECCPRIVATEKEYBLOB�ṹ�е�PrivateKey��	
		// ����Ч����Ϊԭ�ĵģ�uiBits + 7��/8
		OPST_SKF_ECCPUBLICKEYBLOB PubKey;				// ������Կ�ԵĹ�Կ
		OPST_SKF_ECCCIPHERBLOB ECCCipherBlob;			// �ñ�����Կ���ܵĶԳ���Կ���ġ�
	}OPST_SKF_ENVELOPEDKEYBLOB;


#ifdef __cplusplus
}
#endif

#endif /*_O_ALL_TYPE_DEF_H*/
