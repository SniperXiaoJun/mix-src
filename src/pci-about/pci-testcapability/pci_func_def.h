


#ifndef PCI_FUNC_DEF_H_
#define PCI_FUNC_DEF_H_

#include "common.h"

#include "swsds.h"

typedef void * HANDLE;

#ifdef __cplusplus
extern "C" {
#endif


	/*
	功能名称:	生成并导出SM2交换密钥数字信封
	函数名称:	PCI_GenExportSM2EnvelopedKey
	输入参数:	hSessionHandle			会话句柄
				pbPubkeyX				外部签名公钥X（长度必须为32）
				pbPubkeyY				外部签名公钥Y（长度必须为32）
	输出参数:	pvENVELOPEDKEYBLOB_IPK	内部公钥加密的ECC密钥对数字信封(类型为OPST_SKF_ENVELOPEDKEYBLOB)
				pvENVELOPEDKEYBLOB_EPK	外部公钥加密的ECC密钥对数字信封(类型为OPST_SKF_ENVELOPEDKEYBLOB)
	返回值:   
	失败：
	功能描述:	生成并导出SM2交换密钥数字信封
	*/
	COMMON_API unsigned long PCI_GenExportSM2EnvelopedKey(HANDLE hSessionHandle, unsigned char *pbPubkeyX,unsigned char *pbPubkeyY, void * pvENVELOPEDKEYBLOB_IPK, void * pvENVELOPEDKEYBLOB_EPK);

	/*
	功能名称:	导出SM2交换密钥数字信封
	函数名称:	PCI_GenExportSM2EnvelopedKey
	输入参数:	hSessionHandle			会话句柄
				pbPubkeyX				外部签名公钥X（长度必须为32）
				pbPubkeyY				外部签名公钥Y（长度必须为32）
	输出参数:	pvENVELOPEDKEYBLOB_IPK	内部公钥加密的ECC密钥对数字信封(类型为OPST_SKF_ENVELOPEDKEYBLOB)
				pvENVELOPEDKEYBLOB_EPK	外部公钥加密的ECC密钥对数字信封(类型为OPST_SKF_ENVELOPEDKEYBLOB)
	返回值:   
	失败：
	功能描述:	导出SM2交换密钥数字信封
	*/
	COMMON_API unsigned long PCI_RestoreExportSM2EnvelopedKey(HANDLE hSessionHandle, unsigned char *pbPubkeyX,unsigned char *pbPubkeyY, 
		void * pvENVELOPEDKEYBLOB_IPK, void * pvENVELOPEDKEYBLOB_EPK);

	/*
	功能名称:	打开PCI设备
	函数名称:	PCI_Open
	输入参数:	
	输出参数:	phSessionHandle			PCI句柄
				phPCIHandle				会话句柄
	返回值:   
	失败：
	功能描述:	打开PCI设备
	*/
	COMMON_API unsigned long PCI_Open(HANDLE *phPCIHandle, HANDLE *phSessionHandle);

	/*
	功能名称:	关闭PCI设备
	函数名称:	PCI_Close
	输入参数:	hSessionHandle      会话句柄
				hPCIHandle			PCI句柄
	输出参数:
	返回值:   
	失败：
	功能描述:	关闭PCI设备
	*/
	COMMON_API unsigned long PCI_Close(HANDLE hPCIHandle, HANDLE hSessionHandle);

	/*
	功能名称:	IC卡登录
	函数名称:	PCI_ICLogin
	输入参数:	hSessionHandle         会话句柄
				pbPINValue		口令
				ulPINLen			口令长度
	输出参数:	
				pulUserID			用户ID
				pulTrials		错误情况下剩余次数
	返回值:   
	失败：
	功能描述:	IC卡登录
	*/
	COMMON_API unsigned long PCI_ICLogin(HANDLE hSessionHandle,
		const unsigned char* pbPINValue, unsigned long ulPINLen , 
		unsigned long *pulUserID, unsigned long *pulTrials);

	/*
	功能名称:	IC卡登出
	函数名称:	PCI_ICLogout
	输入参数:	hSessionHandle         会话句柄
				ulUserID			用户ID
	输出参数:	
	返回值:   
	失败：
	功能描述:	IC卡登出
	*/
	COMMON_API unsigned long PCI_ICLogout(HANDLE hSessionHandle, unsigned long ulUserID);

	/*
	功能名称:	检测根密钥存在
	函数名称:	PCI_CheckExistRootSM2Keys
	输入参数:	hSessionHandle         会话句柄
	输出参数:
	返回值:   
	失败：
	功能描述:	检测根密钥存在
	*/
	COMMON_API unsigned long PCI_CheckExistRootSM2Keys(HANDLE hSessionHandle);

	/*
	功能名称:	检测根密钥不存在
	函数名称:	PCI_CheckExistRootSM2Keys
	输入参数:	hSessionHandle         会话句柄
	输出参数:
	返回值:   
	失败：
	功能描述:	检测根密钥不存在
	*/
	COMMON_API unsigned long PCI_CheckNotExistRootSM2Keys(HANDLE hSessionHandle);

	/*
	功能名称:	生成根密钥
	函数名称:	PCI_GenRootSM2Keys
	输入参数:	hSessionHandle         会话句柄
	输出参数:
	返回值:   
	失败：
	功能描述:	生成根密钥
	*/
	COMMON_API unsigned long PCI_GenRootSM2Keys(HANDLE hSessionHandle,unsigned char *pbCipherValue, unsigned long *pulCipherLen);

	/*
	功能名称:	导出公钥
	函数名称:	PCI_ExportRootSM2Keys
	输入参数:	hSessionHandle         会话句柄
	输出参数:	pbPubKeyX		公钥X值
				pulPubKeyLenX		公钥X长度
				pbPubKeyY		公钥Y值
				pulPubKeyLenY		公钥Y长度
	返回值:   
	失败：
	功能描述:	导出公钥
	*/
	COMMON_API unsigned long PCI_ExportRootSM2Keys(HANDLE hSessionHandle, unsigned char *pbPubKeyX, unsigned long *pulPubKeyLenX,
		unsigned char *pbPubKeyY, unsigned long *pulPubKeyLenY);

	/*
	功能名称:	生成密钥
	函数名称:	PCI_GenSM2Keys
	输入参数:	hSessionHandle         会话句柄
	输出参数:
	返回值:   
	失败：
	功能描述:	生成密钥
	*/
	COMMON_API unsigned long PCI_GenSM2Keys(HANDLE hSessionHandle,unsigned char *pbCipherValue, unsigned long *pulCipherLen);


	/*
	功能名称:	根密钥签名
	函数名称:	PCI_SignWithRootSM2Keys
	输入参数:	hSessionHandle         会话句柄
				pbPW		私钥访问密码
				ulPWLen			私钥访问密码长度
				pbInValue		签名原文
				ulInLen			签名原文长度
	输出参数:
				pbSigValue		签名值文
				pulSigLen		签名值文长度
	返回值:   
	失败：
	功能描述:	根密钥签名
	*/
	COMMON_API unsigned long PCI_SignWithRootSM2Keys(HANDLE hSessionHandle, 
		const unsigned char * pbPW, unsigned long ulPWLen,
		const unsigned char *pbInValue, unsigned long ulInLen,unsigned long ulAlg,
		unsigned char * pbSigValue, unsigned long * pulSigLen
		);

	/*
	功能名称:	外部私钥签名
	函数名称:	PCI_SignWithSM2Keys
	输入参数:	hSessionHandle         会话句柄
				pbPrivateKey	私钥
				ulPrivateKeyLen		私钥长度
				pbInValue		签名原文
				ulInLen			签名原文长度
	输出参数:	
				pbSigValue		签名值文
				pulSigLen		签名值文长度
	返回值:   
	失败：
	功能描述:	外部私钥签名
	*/
	COMMON_API unsigned long PCI_SignWithSM2Keys(HANDLE hSessionHandle,
		const unsigned char * pbPrivateKey, unsigned long ulPrivateKeyLen,
		const unsigned char * pbInValue, unsigned long ulInLen,
		unsigned char * pbSigValue, unsigned long * pulSigLen
		);

	/*
	功能名称:	外部公钥验证签名
	函数名称:	PCI_VerifyWithSM2Keys
	输入参数:	hSessionHandle         会话句柄
				pbPubkeyX		公钥X
				ulPubkeyXLen		公钥X长度
				pbPubkeyY		公钥Y
				ulPubkeyYLen		公钥Y长度
				pbInValue		签名原文
				ulInLen			签名原文长度
				pbSigValue		签名值文
				ulSigLen		签名值文长度
	输出参数:	
	返回值:   
	失败：
	功能描述:	外部公钥验证签名
	*/
	COMMON_API unsigned long PCI_VerifyWithSM2Keys(HANDLE hSessionHandle,
		const unsigned char * pbPubkeyX, unsigned long ulPubkeyXLen,
		const unsigned char * pbPubkeyY, unsigned long ulPubkeyYLen,
		const unsigned char * pbInValue, unsigned long ulInLen,
		const unsigned char * pbSigValue, unsigned long ulSigLen
		);

	/*
	功能名称:	备份初始化
	函数名称:	PCI_BackupInit
	输入参数:	hSessionHandle         会话句柄
	输出参数:	
	返回值:   
	失败：
	功能描述:	备份初始化
	*/
	COMMON_API unsigned long PCI_BackupInit(HANDLE hSessionHandle);

	/*
	功能名称:	备份分量
	函数名称:	PCI_BackupAuthor
	输入参数:	hSessionHandle         会话句柄
				pbPinValue		口令
				ulPinLen			口令长度
	输出参数:	
	返回值:   
	失败：
	功能描述:	备份授权
	*/
	COMMON_API unsigned long PCI_BackupKeyComponent(HANDLE hSessionHandle, unsigned long ulNumber, 
		const unsigned char *pbPinValue, unsigned long ulPinLen, unsigned long *pulTrials);

	/*
	功能名称:	备份
	函数名称:	PCI_BackupECC
	输入参数:	hSessionHandle         会话句柄
	输出参数:	
				pbCipherValue	密文ECC密钥内容
				ulCipherLen		密文ECC密钥长度
	返回值:   
	失败：
	功能描述:	备份
	*/
	COMMON_API unsigned long PCI_BackupECC(HANDLE hSessionHandle, unsigned long bFlagSign,
		unsigned char *pbCipherValue, unsigned long *pulCipherLen);
	
	/*
	功能名称:	备份结束
	函数名称:	PCI_BackupFinal
	输入参数:	hSessionHandle         会话句柄
	输出参数:	
	返回值:   
	失败：
	功能描述:	备份结束
	*/
	COMMON_API unsigned long PCI_BackupFinal(HANDLE hSessionHandle);

	/*
	功能名称:	恢复初始化
	函数名称:	PCI_RestoreInit
	输入参数:	hSessionHandle         会话句柄
	输出参数:	
	返回值:   
	失败：
	功能描述:	恢复初始化
	*/
	COMMON_API unsigned long PCI_RestoreInit(HANDLE hSessionHandle);

	/*
	功能名称:	恢复分量
	函数名称:	PCI_RestoreAuthor
	输入参数:	hSessionHandle         会话句柄
				pbPinValue		口令
				ulPinLen			口令长度
	输出参数:	
	返回值:   
	失败：
	功能描述:	恢复分量
	*/
	COMMON_API unsigned long PCI_RestoreKeyComponent(HANDLE hSessionHandle, 
		const unsigned char *pbPinValue, unsigned long ulPinLen, unsigned long * pulTrials);
	
	/*
	功能名称:	恢复
	函数名称:	PCI_RestoreECC
	输入参数:	hSessionHandle         会话句柄
				pbCipherValue	密文ECC密钥内容
				ulCipherLen		密文ECC密钥长度
	输出参数:	
	返回值:   
	失败：
	功能描述:	恢复
	*/
	COMMON_API unsigned long PCI_RestoreECC(HANDLE hSessionHandle, unsigned long bFlagSign,
		const unsigned char *pbCipherValue, unsigned long ulCipherLen);

	/*
	功能名称:	恢复结束
	函数名称:	PCI_RestoreFinal
	输入参数:	hSessionHandle         会话句柄
	输出参数:	
	返回值:   
	失败：
	功能描述:	恢复结束
	*/
	COMMON_API unsigned long PCI_RestoreFinal(HANDLE hSessionHandle);


#ifdef __cplusplus
}
#endif

#endif /* PCI_FUNC_DEF_H_ */