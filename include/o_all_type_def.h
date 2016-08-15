#ifndef _O_ALL_TYPE_DEF_H
#define _O_ALL_TYPE_DEF_H

#include "common.h"

#define EXT_COPY_NONE		0
#define EXT_COPY_ADD		1
#define EXT_COPY_ALL		2

// 最多支持设备个数
#define MAX_DEV_NUM	16
#define MAX_CON_NUM 1024    // 每个设备最大容器个数

// SM2私钥长度
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
#define ECC_MAX_XCOORDINATE_BITS_LEN 512	//ECC算法X坐标的最大长度
#define ECC_MAX_YCOORDINATE_BITS_LEN 512	//ECC算法Y坐标的最大长度
////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////
// Copy from pci define
/*ECC密钥*/
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
		OPE_ERR_OK							=	0x00000000,						// 正确

		OPE_ERR_BASE						=	0x1FF10000,

		/////////////////////// Common ERR
		OPE_ERR_INVALID_PARAM				=	(OPE_ERR_BASE+0x00000001)	,	// 参数错误
		OPE_ERR_NOT_ENOUGH_MEMORY			=	(OPE_ERR_BASE+0x00000002)	,	// 电脑内存不足
		OPE_ERR_BUFF_SMALL					=	(OPE_ERR_BASE+0x00000003)	,	// 用户传入的Buffer太小

		/////////////////////// PKCS11 ERR
		OPE_ERR_LIB_NOT_INITED				=	(OPE_ERR_BASE+0x00000101)	,	// 接口库未初始化
		OPE_ERR_NO_DEV						=	(OPE_ERR_BASE+0x00000102)	,	// 未发现卡设备
		OPE_ERR_CONNECT_STATE				=	(OPE_ERR_BASE+0x00000103)	,	// 设备连接状态失效,需要重新Initialize(初始化)
		OPE_ERR_NOT_LOGGED_IN				=	(OPE_ERR_BASE+0x00000104)	,	// 用户未登录
		OPE_ERR_NO_CERT						=	(OPE_ERR_BASE+0x00000105)	,	// 无证书
		OPE_ERR_NO_PRIVKEY					=	(OPE_ERR_BASE+0x00000106)	,	// 无私钥
		OPE_ERR_INVALID_KEYLEN				=	(OPE_ERR_BASE+0x00000107)	,	// 密钥长度错误
		OPE_ERR_NO_SUPPORT_RSA_MODULUS		=	(OPE_ERR_BASE+0x00000108)	,	// RSA密钥长度不支持(非1024或非2048的密钥)
		OPE_ERR_CONNECT_DEV					=   (OPE_ERR_BASE+0x00000109)	,	// 连接设备出错
		OPE_ERR_OPEN_APPLICATION			=   (OPE_ERR_BASE+0x0000010A)	,   // 打开应用出错
		OPE_ERR_INITIALIZE_P11				=   (OPE_ERR_BASE+0x0000010B)	,   // 初始化P11出错
		OPE_ERR_FINALIZE_P11				=   (OPE_ERR_BASE+0x0000010C)	,   // 卸载P11出错
		OPE_ERR_DEV_MEM_NOT_ENOUGH			=   (OPE_ERR_BASE+0x0000010D)	,	// 设备内存不足
		OPE_ERR_NO_CONTAINER				=   (OPE_ERR_BASE+0x0000010F)	,   // 容器不存在
		OPE_ERR_DEV_NUMBER_ERR				=   (OPE_ERR_BASE+0x00000110)	,   // 设备个数不正确
		OPE_ERR_DEV_NUMBER_ZERO             =   (OPE_ERR_BASE+0x00000111)   ,   // 未插入设备

		///////////////////// OpenSSL ERR
		OPE_ERR_VERIFY_CSR					=   (OPE_ERR_BASE+0x00000201)	,   // 验证失败
		OPE_ERR_INITIALIZE_OPENSSL			=   (OPE_ERR_BASE+0x00000202)	,   // 初始化P11出错
		OPE_ERR_FINALIZE_OPENSSL			=   (OPE_ERR_BASE+0x00000203)	,   // 卸载P11出错

		//////////////////// PCI ERR
		OPE_ERR_PCI_NOT_INIT				=   (OPE_ERR_BASE+0x00000301)	,  // 未初始化
		OPE_ERR_PCI_CHECK_ROOTSM2KEY_EXIST  =   (OPE_ERR_BASE+0x00000302), //密钥存在
		OPE_ERR_PCI_CHECK_ROOTSM2KEY_NOT_EXIST=	(OPE_ERR_BASE+0x00000303),


		OPE_ERR_UNKNOWN						=	(OPE_ERR_BASE+0x00000FFF)	,	// 未知错误


		PCI_PARAM_ERR = 0x0F000001,
		PCI_CARD_NO_FIND_IC = 0x0F000006,	// 未找到IC卡
		PCI_CARD_INSERT_ERR = 0x0F000007,// IC插入方向错误或不到位
		PCI_CARD_RIGHT_ERR = 0x0F000008,	// 操作权限不满足
		PCI_CARD_IC_PIN_ERR = 0x0F000009,	// IC卡口令错误
		PCI_CARD_IC_PIN_LOCK_ERR = 0x0F00000A,// IC卡已锁死	


		/*标准错误码定义*/
		PCI_SDR_BASE = 0x01000000,
		PCI_SDR_UNKNOWERR = (PCI_SDR_BASE + 0x00000001),	   /*未知错误*/
		PCI_SDR_NOTSUPPORT = (PCI_SDR_BASE + 0x00000002),	   /*不支持*/
		PCI_SDR_COMMFAIL = (PCI_SDR_BASE + 0x00000003),    /*通信错误*/
		PCI_SDR_HARDFAIL = (PCI_SDR_BASE + 0x00000004),    /*硬件错误*/
		PCI_SDR_OPENDEVICE = (PCI_SDR_BASE + 0x00000005),    /*打开设备错误*/
		PCI_SDR_OPENSESSION = (PCI_SDR_BASE + 0x00000006),    /*打开会话句柄错误*/
		PCI_SDR_PARDENY = (PCI_SDR_BASE + 0x00000007),    /*权限不满足*/
		PCI_SDR_KEYNOTEXIST = (PCI_SDR_BASE + 0x00000008),    /*密钥不存在*/
		PCI_SDR_ALGNOTSUPPORT = (PCI_SDR_BASE + 0x00000009),    /*不支持的算法*/
		PCI_SDR_ALGMODNOTSUPPORT = (PCI_SDR_BASE + 0x0000000A),    /*不支持的算法模式*/
		PCI_SDR_PKOPERR = (PCI_SDR_BASE + 0x0000000B),    /*公钥运算错误*/
		PCI_SDR_SKOPERR = (PCI_SDR_BASE + 0x0000000C),    /*私钥运算错误*/
		PCI_SDR_SIGNERR = (PCI_SDR_BASE + 0x0000000D),    /*签名错误*/
		PCI_SDR_VERIFYERR = (PCI_SDR_BASE + 0x0000000E),    /*验证错误*/
		PCI_SDR_SYMOPERR = (PCI_SDR_BASE + 0x0000000F),    /*对称运算错误*/
		PCI_SDR_STEPERR = (PCI_SDR_BASE + 0x00000010),    /*步骤错误*/
		PCI_SDR_FILESIZEERR = (PCI_SDR_BASE + 0x00000011),    /*文件大小错误或输入数据长度非法*/
		PCI_SDR_FILENOEXIST = (PCI_SDR_BASE + 0x00000012),    /*文件不存在*/
		PCI_SDR_FILEOFSERR = (PCI_SDR_BASE + 0x00000013),    /*文件操作偏移量错误*/
		PCI_SDR_KEYTYPEERR = (PCI_SDR_BASE + 0x00000014),    /*密钥类型错误*/
		PCI_SDR_KEYERR = (PCI_SDR_BASE + 0x00000015),    /*密钥错误*/

		/*============================================================*/
		/*扩展错误码*/
		PCI_SWR_BASE = (PCI_SDR_BASE + 0x00010000),	/*自定义错误码基础值*/
		PCI_SWR_INVALID_USER = (PCI_SWR_BASE + 0x00000001),	/*无效的用户名*/
		PCI_SWR_INVALID_AUTHENCODE = (PCI_SWR_BASE + 0x00000002),	/*无效的授权码*/
		PCI_SWR_PROTOCOL_VER_ERR = (PCI_SWR_BASE + 0x00000003),	/*不支持的协议版本*/
		PCI_SWR_INVALID_COMMAND = (PCI_SWR_BASE + 0x00000004),	/*错误的命令字*/
		PCI_SWR_INVALID_PARAMETERS = (PCI_SWR_BASE + 0x00000005),	/*参数错误或错误的数据包格式*/
		PCI_SWR_FILE_ALREADY_EXIST = (PCI_SWR_BASE + 0x00000006),	/*已存在同名文件*/
		PCI_SWR_SYNCH_ERR = (PCI_SWR_BASE + 0x00000007),	/*多卡同步错误*/
		PCI_SWR_SYNCH_LOGIN_ERR = (PCI_SWR_BASE + 0x00000008),	/*多卡同步后登录错误*/

		PCI_SWR_SOCKET_TIMEOUT = (PCI_SWR_BASE + 0x00000100),	/*超时错误*/
		PCI_SWR_CONNECT_ERR = (PCI_SWR_BASE + 0x00000101),	/*连接服务器错误*/
		PCI_SWR_SET_SOCKOPT_ERR = (PCI_SWR_BASE + 0x00000102),	/*设置Socket参数错误*/
		PCI_SWR_SOCKET_SEND_ERR = (PCI_SWR_BASE + 0x00000104),	/*发送LOGINRequest错误*/
		PCI_SWR_SOCKET_RECV_ERR = (PCI_SWR_BASE + 0x00000105),	/*发送LOGINRequest错误*/
		PCI_SWR_SOCKET_RECV_0 = (PCI_SWR_BASE + 0x00000106),	/*发送LOGINRequest错误*/

		PCI_SWR_SEM_TIMEOUT = (PCI_SWR_BASE + 0x00000200),	/*超时错误*/
		PCI_SWR_NO_AVAILABLE_HSM = (PCI_SWR_BASE + 0x00000201),	/*没有可用的加密机*/
		PCI_SWR_NO_AVAILABLE_CSM = (PCI_SWR_BASE + 0x00000202),	/*加密机内没有可用的加密模块*/

		PCI_SWR_CONFIG_ERR = (PCI_SWR_BASE + 0x00000301),	/*配置文件错误*/

		/*============================================================*/
		/*密码卡错误码*/
		PCI_SWR_CARD_BASE = (PCI_SDR_BASE + 0x00020000),			/*密码卡错误码*/
		PCI_SWR_CARD_UNKNOWERR = (PCI_SWR_CARD_BASE + 0x00000001),	//未知错误
		PCI_SWR_CARD_NOTSUPPORT = (PCI_SWR_CARD_BASE + 0x00000002),	//不支持的接口调用
		PCI_SWR_CARD_COMMFAIL = (PCI_SWR_CARD_BASE + 0x00000003),	//与设备通信失败
		PCI_SWR_CARD_HARDFAIL = (PCI_SWR_CARD_BASE + 0x00000004),	//运算模块无响应
		PCI_SWR_CARD_OPENDEVICE = (PCI_SWR_CARD_BASE + 0x00000005),	//打开设备失败
		PCI_SWR_CARD_OPENSESSION = (PCI_SWR_CARD_BASE + 0x00000006),	//创建会话失败
		PCI_SWR_CARD_PARDENY = (PCI_SWR_CARD_BASE + 0x00000007),	//无私钥使用权限
		PCI_SWR_CARD_KEYNOTEXIST = (PCI_SWR_CARD_BASE + 0x00000008),	//不存在的密钥调用
		PCI_SWR_CARD_ALGNOTSUPPORT = (PCI_SWR_CARD_BASE + 0x00000009),	//不支持的算法调用
		PCI_SWR_CARD_ALGMODNOTSUPPORT = (PCI_SWR_CARD_BASE + 0x00000010),	//不支持的算法调用
		PCI_SWR_CARD_PKOPERR = (PCI_SWR_CARD_BASE + 0x00000011),	//公钥运算失败
		PCI_SWR_CARD_SKOPERR = (PCI_SWR_CARD_BASE + 0x00000012),	//私钥运算失败
		PCI_SWR_CARD_SIGNERR = (PCI_SWR_CARD_BASE + 0x00000013),	//签名运算失败
		PCI_SWR_CARD_VERIFYERR = (PCI_SWR_CARD_BASE + 0x00000014),	//验证签名失败
		PCI_SWR_CARD_SYMOPERR = (PCI_SWR_CARD_BASE + 0x00000015),	//对称算法运算失败
		PCI_SWR_CARD_STEPERR = (PCI_SWR_CARD_BASE + 0x00000016),	//多步运算步骤错误
		PCI_SWR_CARD_FILESIZEERR = (PCI_SWR_CARD_BASE + 0x00000017),	//文件长度超出限制
		PCI_SWR_CARD_FILENOEXIST = (PCI_SWR_CARD_BASE + 0x00000018),	//指定的文件不存在
		PCI_SWR_CARD_FILEOFSERR = (PCI_SWR_CARD_BASE + 0x00000019),	//文件起始位置错误
		PCI_SWR_CARD_KEYTYPEERR = (PCI_SWR_CARD_BASE + 0x00000020),	//密钥类型错误
		PCI_SWR_CARD_KEYERR = (PCI_SWR_CARD_BASE + 0x00000021),	//密钥错误
		PCI_SWR_CARD_BUFFER_TOO_SMALL = (PCI_SWR_CARD_BASE + 0x00000101),	//接收参数的缓存区太小
		PCI_SWR_CARD_DATA_PAD = (PCI_SWR_CARD_BASE + 0x00000102),	//数据没有按正确格式填充，或解密得到的脱密数据不符合填充格式
		PCI_SWR_CARD_DATA_SIZE = (PCI_SWR_CARD_BASE + 0x00000103),	//明文或密文长度不符合相应的算法要求
		PCI_SWR_CARD_CRYPTO_NOT_INIT = (PCI_SWR_CARD_BASE + 0x00000104),	//该错误表明没有为相应的算法调用初始化函数

		//01/03/09版密码卡权限管理错误码
		PCI_SWR_CARD_MANAGEMENT_DENY = (PCI_SWR_CARD_BASE + 0x00001001),	//管理权限不满足
		PCI_SWR_CARD_OPERATION_DENY = (PCI_SWR_CARD_BASE + 0x00001002),	//操作权限不满足
		PCI_SWR_CARD_DEVICE_STATUS_ERR = (PCI_SWR_CARD_BASE + 0x00001003),	//当前设备状态不满足现有操作
		PCI_SWR_CARD_LOGIN_ERR = (PCI_SWR_CARD_BASE + 0x00001011),	//登录失败
		PCI_SWR_CARD_USERID_ERR = (PCI_SWR_CARD_BASE + 0x00001012),	//用户ID数目/号码错误
		PCI_SWR_CARD_PARAMENT_ERR = (PCI_SWR_CARD_BASE + 0x00001013),	//参数错误

		//05/06版密码卡权限管理错误码
		PCI_SWR_CARD_MANAGEMENT_DENY_05 = (PCI_SWR_CARD_BASE + 0x00000801),	//管理权限不满足
		PCI_SWR_CARD_OPERATION_DENY_05 = (PCI_SWR_CARD_BASE + 0x00000802),	//操作权限不满足
		PCI_SWR_CARD_DEVICE_STATUS_ERR_05 = (PCI_SWR_CARD_BASE + 0x00000803),	//当前设备状态不满足现有操作
		PCI_SWR_CARD_LOGIN_ERR_05 = (PCI_SWR_CARD_BASE + 0x00000811),	//登录失败
		PCI_SWR_CARD_USERID_ERR_05 = (PCI_SWR_CARD_BASE + 0x00000812),	//用户ID数目/号码错误
		PCI_SWR_CARD_PARAMENT_ERR_05 = (PCI_SWR_CARD_BASE + 0x00000813),	//参数错误

		/*============================================================*/
		/*读卡器错误*/
		PCI_SWR_CARD_READER_BASE = (PCI_SDR_BASE + 0x00030000),	//	读卡器类型错误
		PCI_SWR_CARD_READER_PIN_ERROR = (PCI_SWR_CARD_READER_BASE + 0x000063CE),  //口令错误
		PCI_SWR_CARD_READER_NO_CARD = (PCI_SWR_CARD_READER_BASE + 0x0000FF01),	 //	IC未插入
		PCI_SWR_CARD_READER_CARD_INSERT = (PCI_SWR_CARD_READER_BASE + 0x0000FF02),	 //	IC插入方向错误或不到位
		PCI_SWR_CARD_READER_CARD_INSERT_TYPE = (PCI_SWR_CARD_READER_BASE + 0x0000FF03),	 //	IC类型错误

	}OPE_ERR;

	// 密钥类型
	typedef enum _OPE_KEY_TYPE { 
		OPE_KEY_TYPE_SM2, OPE_KEY_TYPE_RSA, OPE_KEY_TYPE_EC,
	} OPE_KEY_TYPE;


	typedef enum _OPE_CON_TYPE
	{
		OPE_CON_TYPE_SIGN =0,OPE_CON_TYPE_ENCYPT = 1,
	}OPE_CON_TYPE;
	
	typedef enum _OPE_ENCODE_TYPE { 
		OPE_ENCODE_TYPE_DER = 0,	   	// 文件编码类型: DER
		OPE_ENCODE_TYPE_PEM,			// 文件编码类型: PEM
	} OPE_ENCODE_TYPE;

	// 用户基本信息
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
		unsigned char sn[128];		// 序列号
		unsigned char snlen;
		unsigned int reason_code;	// 原由
		unsigned long dt;				// 日期时间
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

	// 设备
	typedef struct _OPST_DEV
	{
		unsigned int	uiSlotID;
		unsigned int	hSession;
		// 用户是否已登录
		unsigned char		bLoginState;
		// 硬件信息
		OPST_CK_SLOT_INFO	slotInfo;
	} OPST_DEV;

	// 容器
	typedef struct _OPST_CONTAINER
	{
		// 容器名长度 + 容器类型  例： 容器名为1234  加密为1234+0 签名为1234+1
		char szName[MAX_CON_NAME_LEN + 1];
		// 容器名长度 + 1(类型长度)
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


	// USB使用类型
	typedef enum _OPE_USB_META_USE_TYPE
	{
		OPE_USB_META_USE_TYPE_AUTH = 0 , //认证登录KEY
		OPE_USB_META_USE_TYPE_CERT = 1 , //证书KEY
	}OPE_USB_META_USE_TYPE;

	// USB使用类型
	typedef enum _OPE_USB_TARGET
	{
		OPE_USB_TARGET_SELF = 0 ,  //当前KEY
		OPE_USB_TARGET_OTHER = 1 , //非当前KEY
	}OPE_USB_TARGET;

	// USB管理类型
	typedef enum _OPE_USB_META_MAN_TYPE
	{
		OPE_USB_META_MAN_TYPE_ADMIN   = 1,
		OPE_USB_META_MAN_TYPE_OP      = 2,
		OPE_USB_META_MAN_TYPE_AUDIT   = 3,
	}OPE_USB_META_MAN_TYPE;

	typedef struct _OPT_ST_USB_META
	{
		unsigned int uiUSBMetaUseType;  // USB使用类型 OPE_USB_META_USE_TYPE
		unsigned int uiUSBMetaManType;  // USB管理类型 OPE_USB_META_MAN_TYPE
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
		OPT_UInt32	BitLen;											//模数的实际位长度	必须是8的倍数
		OPT_Byte	XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8];	//曲线上点的X坐标	有限域上的整数
		OPT_Byte	YCoordinate[ECC_MAX_YCOORDINATE_BITS_LEN/8];	//曲线上点的Y坐标	有限域上的整数
	}OPST_SKF_ECCPUBLICKEYBLOB;

	// == SKF ECCCIPHERBLOB
	typedef struct _OPST_SKF_ECCCIPHERBLOB{
		OPT_Byte  XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8];		//与y组成椭圆曲线上的点（x，y）
		OPT_Byte  YCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8];		//与x组成椭圆曲线上的点（x，y）
		OPT_Byte  HASH[32];											//明文的杂凑值
		OPT_UInt32	CipherLen;										//密文数据长度
		OPT_Byte  Cipher[SM2_BYTES_LEN];							//密文数据	实际长度为CipherLen			
	} OPST_SKF_ECCCIPHERBLOB;

	
	// == SKF_ENVELOPEDKEYBLOB(SKF)
	typedef struct _OPST_SKF_ENVELOPEDKEYBLOB{
		OPT_UInt32 Version;							// 当前版本为 1
		OPT_UInt32 uiSymmAlgID;						// 对称算法标识，限定ECB模式
		OPT_UInt32 uiBits;							// 加密密钥对的密钥位长度
		OPT_Byte cbEncryptedPriKey[64];			// 对称算法加密的加密私钥,加密私钥的原文为ECCPRIVATEKEYBLOB结构中的PrivateKey。	
		// 其有效长度为原文的（uiBits + 7）/8
		OPST_SKF_ECCPUBLICKEYBLOB PubKey;				// 加密密钥对的公钥
		OPST_SKF_ECCCIPHERBLOB ECCCipherBlob;			// 用保护公钥加密的对称密钥密文。
	}OPST_SKF_ENVELOPEDKEYBLOB;


#ifdef __cplusplus
}
#endif

#endif /*_O_ALL_TYPE_DEF_H*/
