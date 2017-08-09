/******************************************************************************
******************************************************************************/

#include <windows.h>

// 最大支持个数
#define SCCRYPT_TF_MAX_DEV_NUM             26
// 名称最大长度
#define SCCRYPT_TF_MAX_DEV_NAME_LEN        33


// 唯一序列号的长度
#define SCCRYPT_SN_LEN                     8


#ifdef __cplusplus
extern "C" {
#endif



// 枚举TF设备
// 参数：
//   pszDrives：返回TF设备，多字符串，如果为NULL，pulDrivesLen将返回所需buffer的大小
//   pulDrivesLen：用来指明buffer pszDrives的大小
//   pulDriveNum：返回UKey设备个数
// 返回值：
//   函数执行成功，将返回0，否则返回相应的错误码
// 返回值：
//   成功返回0，否则返回相应的错误码
DWORD __stdcall SC_ListDevs
(
	OUT char *pszDrives,
	IN OUT DWORD *pulDrivesLen,
	OUT DWORD *pulDriveNum
);


// 连接设备
// 参数
//   pszDrive：由SC_ListDevs枚举到的UKey设备
//   phDevice：返回设备描述符
// 返回值：
//   函数执行成功，将返回0，否则返回相应的错误码
DWORD __stdcall SC_ConnectDev
(
	IN char *pszDrive,
	OUT HANDLE *phDevice
);


// 断开设备的连接
// 参数：
//   hDevice：由SC_ConnectDev返回的设备描述符
// 返回值：
//   成功返回0，否则返回相应的错误码
DWORD __stdcall SC_DisconnectDev
(
	IN HANDLE hDevice
);


// 获取TF卡唯一序列号
// 参数：
//   hDevice：由SC_ConnectDev返回的设备描述符
//   pbSN：返回序列号，第一个字节为公钥Index
//   pulSNLen：返回序列号的长度，序列号长度为TFCRYPT_SN_LEN
// 返回值：
//   成功返回0，否则返回相应的错误码
DWORD __stdcall SC_GetSCSN
(
	IN HANDLE hDevice,
	OUT BYTE *pbSN,
	IN OUT DWORD *pulSNLen
);



// 验证PIN，暂定明文的方式验证
// 参数：
//   hDevice：由SC_ConnectDev返回的设备描述符
//   pbPIN：PIN码
//   ulPINLen：PIN码长度
//   pulTrials：如果PIN码输入错误, 则返回还可以重试的次数
// 返回值：
//   成功返回0，否则返回相应的错误码
DWORD __stdcall SC_VerifyPIN
(
	IN HANDLE hDevice,
	IN BYTE *pbPIN,
	IN DWORD ulPINLen,
	OUT DWORD *pulTrials
);


/*
// 生成SM2密钥对，并导出公钥
// 参数：
//   hDevice：由SC_ConnectDev返回的设备描述符
//   pbPubKey：输出公钥数据
//   pulPubKeyLen：输出公钥数据长度
// 返回值：
//   成功返回0，否则返回相应的错误码
DWORD __stdcall SC_GenSM2KeyPair
(
	IN HANDLE hDevice,
	IN BYTE *pbPubKey,
	IN OUT DWORD *pulPubKeyLen
);
*/

// 导出SM2公钥
// 参数：
//   hDevice：由SC_ConnectDev返回的设备描述符
//   pbPubKey：输出公钥数据
//   pulPubKeyLen：输出公钥数据长度
// 返回值：
//   成功返回0，否则返回相应的错误码
DWORD __stdcall SC_ExportSM2PubKey
(
	IN HANDLE hDevice,
	IN BYTE *pbPubKey,
	IN OUT DWORD *pulPubKeyLen
);




// 安装SM9密钥对
//   hDevice：由SC_ConnectDev返回的设备描述符
//   ulIndex：用户密钥对Index
//   pbUserID：用户ID
//   ulUserIDLen：用户ID长度
//   pbPubKeySign：签名公钥（明文）
//   ulPubKeySignLen：签名公钥长度
//   pbPriKeySign：密文签名私钥（SM2公钥加密）
//   ulPriKeySignLen：密文签名私钥长度
//   pbPubKeyExc：交换公钥（明文）
//   ulPubKeyExcLen：交换公钥长度
//   pbPriKeyExc：密文交换私钥（SM2公钥加密）
//   ulPriKeyExcLen：密文交换私钥长度
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


// 读取用户身份ID
// 读取证书数据
// 参数：
//   hDevice：由SC_ConnectDev返回的设备描述符
//   ulIndex：待读取的证书索引号，从0开始
//   pbID：返回用户身份ID
//   pulIDLen：返回用户身份长度
// 返回值：
//   成功返回0，否则返回相应的错误码
DWORD __stdcall SC_GetUserID
(
	IN HANDLE hDevice, 
	IN DWORD ulIndex,
	OUT BYTE *pbID,
	IN OUT DWORD *pulIDLen
);



// 签名
//   hDevice：由SC_ConnectDev返回的设备描述符
//   ulIndex: 密钥对Index
//   pbInData：待签名数据
//   ulInDataLen：待签名数据长度
//   pbSignature：输出签名值
//   pulSignLen：输出签名值的长度
DWORD __stdcall SC_SM9Sign
(
	IN HANDLE hDevice,
	IN DWORD ulIndex,
	IN BYTE *pbInData,
	IN DWORD ulInDataLen,
	OUT BYTE *pbSignature,
	IN OUT DWORD *pulSignLen
);



// 验签
//   hDevice：由SC_ConnectDev返回的设备描述符
//   ulIndex: 密钥对Index
//   pbUserID：签名者用户ID
//   ulUserIDLen：签名者用户ID长度
//   pbInData：待验证签名的数据
//   ulInDataLen：数据长度
//   pbSignature：待验证的签名值
//   pulSignLen：待验证的签名值长度
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




// 生成SessionKey用对方公钥加密导出
//   hDevice：由SC_ConnectDev返回的设备描述符
//   ulIndex: 密钥对Index
//   pbUserID：用户ID
//   ulUserIDLen：用户ID长度
//   pbCipherSK：输出SessionKey密文
//   pulCipherSKLen：输出SessionKey密文长度
DWORD __stdcall SC_ExportSessionKey
(
	IN HANDLE hDevice,
	
	IN DWORD ulIndex,

	IN BYTE *pbUserID,
	IN DWORD ulUserIDLen,

	OUT BYTE *pbCipherSK,
	IN OUT DWORD *pulCipherSKLen
);


// 导入SessionKey
//   hDevice：由SC_ConnectDev返回的设备描述符
//   ulIndex: 密钥对Index
//   pbUserID：用户ID
//   ulUserIDLen：用户ID长度
//   pbCipherSK：SessionKey密文
//   ulCipherSKLen：SessionKey密文长度
DWORD __stdcall SC_ImportSessionKey
(
	IN HANDLE hDevice,
	IN DWORD ulIndex,
	IN BYTE *pbUserID,
	IN DWORD ulUserIDLen,
	OUT BYTE *pbCipherSK,
	IN DWORD ulCipherSKLen
);


// 算法初始化
//   hDevice：由SC_ConnectDev返回的设备描述符
DWORD __stdcall SC_CryptInit
(
	IN HANDLE hDevice
);


// 加密数据
//   hDevice：由SC_ConnectDev返回的设备描述符
//   pbCount：加密计数
//   ulCountLen：加密计数长度
//   pbPlaintext：明文数据
//   ulPlaintextLen：明文数据长度
//   pbCiphertext：返回密文
//   pulPlaintextLen：返回密文数据长度
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


// 解密数据
//   hDevice：由SC_ConnectDev返回的设备描述符
//   pbCount：解密计数
//   ulCountLen：解密计数长度
//   pbCiphertext：密文数据
//   ulPlaintextLen：密文数据长度
//   pbPlaintext：返回明文数据
//   pulPlaintextLen：返回明文数据长度
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


// 算法结束
//   hDevice：由SC_ConnectDev返回的设备描述符
DWORD __stdcall SC_CryptFinal
(
	IN HANDLE hDevice
);


#ifdef __cplusplus
}
#endif

