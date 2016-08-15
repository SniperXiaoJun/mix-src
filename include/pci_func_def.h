


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
	COMMON_API unsigned int PCI_GenExportSM2EnvelopedKey(HANDLE hSessionHandle, unsigned char *pbPubkeyX,unsigned char *pbPubkeyY, void * pvENVELOPEDKEYBLOB_IPK, void * pvENVELOPEDKEYBLOB_EPK);

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
	COMMON_API unsigned int PCI_RestoreExportSM2EnvelopedKey(HANDLE hSessionHandle, unsigned char *pbPubkeyX,unsigned char *pbPubkeyY, 
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
	COMMON_API unsigned int PCI_Open(HANDLE *phPCIHandle, HANDLE *phSessionHandle);

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
	COMMON_API unsigned int PCI_Close(HANDLE hPCIHandle, HANDLE hSessionHandle);

	/*
	功能名称:	IC卡登录
	函数名称:	PCI_ICLogin
	输入参数:	hSessionHandle         会话句柄
				pbPINValue		口令
				uiPINLen			口令长度
	输出参数:	
				puiUserID			用户ID
				puiTrials		错误情况下剩余次数
	返回值:   
	失败：
	功能描述:	IC卡登录
	*/
	COMMON_API unsigned int PCI_ICLogin(HANDLE hSessionHandle,
		const unsigned char* pbPINValue, unsigned int uiPINLen , 
		unsigned int *puiUserID, unsigned int *puiTrials);

	/*
	功能名称:	IC卡登出
	函数名称:	PCI_ICLogout
	输入参数:	hSessionHandle         会话句柄
				uiUserID			用户ID
	输出参数:	
	返回值:   
	失败：
	功能描述:	IC卡登出
	*/
	COMMON_API unsigned int PCI_ICLogout(HANDLE hSessionHandle, unsigned int uiUserID);

	/*
	功能名称:	检测根密钥存在
	函数名称:	PCI_CheckExistRootSM2Keys
	输入参数:	hSessionHandle         会话句柄
	输出参数:
	返回值:   
	失败：
	功能描述:	检测根密钥存在
	*/
	COMMON_API unsigned int PCI_CheckExistRootSM2Keys(HANDLE hSessionHandle);

	/*
	功能名称:	检测根密钥不存在
	函数名称:	PCI_CheckExistRootSM2Keys
	输入参数:	hSessionHandle         会话句柄
	输出参数:
	返回值:   
	失败：
	功能描述:	检测根密钥不存在
	*/
	COMMON_API unsigned int PCI_CheckNotExistRootSM2Keys(HANDLE hSessionHandle);

	/*
	功能名称:	生成根密钥
	函数名称:	PCI_GenRootSM2Keys
	输入参数:	hSessionHandle         会话句柄
	输出参数:
	返回值:   
	失败：
	功能描述:	生成根密钥
	*/
	COMMON_API unsigned int PCI_GenRootSM2Keys(HANDLE hSessionHandle,unsigned char *pbCipherValue, unsigned int *puiCipherLen);

	/*
	功能名称:	导出公钥
	函数名称:	PCI_ExportRootSM2Keys
	输入参数:	hSessionHandle         会话句柄
	输出参数:	pbPubKeyX		公钥X值
				puiPubKeyLenX		公钥X长度
				pbPubKeyY		公钥Y值
				puiPubKeyLenY		公钥Y长度
	返回值:   
	失败：
	功能描述:	导出公钥
	*/
	COMMON_API unsigned int PCI_ExportRootSM2Keys(HANDLE hSessionHandle, unsigned char *pbPubKeyX, unsigned int *puiPubKeyLenX,
		unsigned char *pbPubKeyY, unsigned int *puiPubKeyLenY);

	/*
	功能名称:	生成密钥
	函数名称:	PCI_GenSM2Keys
	输入参数:	hSessionHandle         会话句柄
	输出参数:
	返回值:   
	失败：
	功能描述:	生成密钥
	*/
	COMMON_API unsigned int PCI_GenSM2Keys(HANDLE hSessionHandle,unsigned char *pbCipherValue, unsigned int *puiCipherLen);


	/*
	功能名称:	根密钥签名
	函数名称:	PCI_SignWithRootSM2Keys
	输入参数:	hSessionHandle         会话句柄
				pbPW		私钥访问密码
				uiPWLen			私钥访问密码长度
				pbInValue		签名原文
				uiInLen			签名原文长度
	输出参数:
				pbSigValue		签名值文
				puiSigLen		签名值文长度
	返回值:   
	失败：
	功能描述:	根密钥签名
	*/
	COMMON_API unsigned int PCI_SignWithRootSM2Keys(HANDLE hSessionHandle, 
		const unsigned char * pbPW, unsigned int uiPWLen,
		const unsigned char *pbInValue, unsigned int uiInLen,unsigned int uiAlg,
		unsigned char * pbSigValue, unsigned int * puiSigLen
		);

	/*
	功能名称:	外部私钥签名
	函数名称:	PCI_SignWithSM2Keys
	输入参数:	hSessionHandle         会话句柄
				pbPrivateKey	私钥
				uiPrivateKeyLen		私钥长度
				pbInValue		签名原文
				uiInLen			签名原文长度
	输出参数:	
				pbSigValue		签名值文
				puiSigLen		签名值文长度
	返回值:   
	失败：
	功能描述:	外部私钥签名
	*/
	COMMON_API unsigned int PCI_SignWithSM2Keys(HANDLE hSessionHandle,
		const unsigned char * pbPrivateKey, unsigned int uiPrivateKeyLen,
		const unsigned char * pbInValue, unsigned int uiInLen,
		unsigned char * pbSigValue, unsigned int * puiSigLen
		);

	/*
	功能名称:	外部公钥验证签名
	函数名称:	PCI_VerifyWithSM2Keys
	输入参数:	hSessionHandle         会话句柄
				pbPubkeyX		公钥X
				uiPubkeyXLen		公钥X长度
				pbPubkeyY		公钥Y
				uiPubkeyYLen		公钥Y长度
				pbInValue		签名原文
				uiInLen			签名原文长度
				pbSigValue		签名值文
				uiSigLen		签名值文长度
	输出参数:	
	返回值:   
	失败：
	功能描述:	外部公钥验证签名
	*/
	COMMON_API unsigned int PCI_VerifyWithSM2Keys(HANDLE hSessionHandle,
		const unsigned char * pbPubkeyX, unsigned int uiPubkeyXLen,
		const unsigned char * pbPubkeyY, unsigned int uiPubkeyYLen,
		const unsigned char * pbInValue, unsigned int uiInLen,
		const unsigned char * pbSigValue, unsigned int uiSigLen
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
	COMMON_API unsigned int PCI_BackupInit(HANDLE hSessionHandle);

	/*
	功能名称:	备份分量
	函数名称:	PCI_BackupAuthor
	输入参数:	hSessionHandle         会话句柄
				pbPinValue		口令
				uiPinLen			口令长度
	输出参数:	
	返回值:   
	失败：
	功能描述:	备份授权
	*/
	COMMON_API unsigned int PCI_BackupKeyComponent(HANDLE hSessionHandle, unsigned int uiNumber, 
		const unsigned char *pbPinValue, unsigned int uiPinLen, unsigned int *puiTrials);

	/*
	功能名称:	备份
	函数名称:	PCI_BackupECC
	输入参数:	hSessionHandle         会话句柄
	输出参数:	
				pbCipherValue	密文ECC密钥内容
				uiCipherLen		密文ECC密钥长度
	返回值:   
	失败：
	功能描述:	备份
	*/
	COMMON_API unsigned int PCI_BackupECC(HANDLE hSessionHandle, unsigned int bFlagSign,
		unsigned char *pbCipherValue, unsigned int *puiCipherLen);
	
	/*
	功能名称:	备份结束
	函数名称:	PCI_BackupFinal
	输入参数:	hSessionHandle         会话句柄
	输出参数:	
	返回值:   
	失败：
	功能描述:	备份结束
	*/
	COMMON_API unsigned int PCI_BackupFinal(HANDLE hSessionHandle);

	/*
	功能名称:	恢复初始化
	函数名称:	PCI_RestoreInit
	输入参数:	hSessionHandle         会话句柄
	输出参数:	
	返回值:   
	失败：
	功能描述:	恢复初始化
	*/
	COMMON_API unsigned int PCI_RestoreInit(HANDLE hSessionHandle);

	/*
	功能名称:	恢复分量
	函数名称:	PCI_RestoreAuthor
	输入参数:	hSessionHandle         会话句柄
				pbPinValue		口令
				uiPinLen			口令长度
	输出参数:	
	返回值:   
	失败：
	功能描述:	恢复分量
	*/
	COMMON_API unsigned int PCI_RestoreKeyComponent(HANDLE hSessionHandle, 
		const unsigned char *pbPinValue, unsigned int uiPinLen, unsigned int * puiTrials);
	
	/*
	功能名称:	恢复
	函数名称:	PCI_RestoreECC
	输入参数:	hSessionHandle         会话句柄
				pbCipherValue	密文ECC密钥内容
				uiCipherLen		密文ECC密钥长度
	输出参数:	
	返回值:   
	失败：
	功能描述:	恢复
	*/
	COMMON_API unsigned int PCI_RestoreECC(HANDLE hSessionHandle, unsigned int bFlagSign,
		const unsigned char *pbCipherValue, unsigned int uiCipherLen);

	/*
	功能名称:	恢复结束
	函数名称:	PCI_RestoreFinal
	输入参数:	hSessionHandle         会话句柄
	输出参数:	
	返回值:   
	失败：
	功能描述:	恢复结束
	*/
	COMMON_API unsigned int PCI_RestoreFinal(HANDLE hSessionHandle);


#ifdef __cplusplus
}
#endif

#endif /* PCI_FUNC_DEF_H_ */