
#ifndef _O_ALL_FUNC_DEF_H_
#define _O_ALL_FUNC_DEF_H_

#include "common.h"

#include "o_all_type_def.h"		// 类型定义

#ifdef __cplusplus
extern "C" {
#endif
	/*
	功能名称:	初始化资源
	函数名称:	OPF_Initialize
	输入参数:	
	输出参数:	
	返回值:   
	失败：
	功能描述:	初始化资源全局变量，打开P11_SESSION|OPEN_SSL
	*/
	COMMON_API unsigned int OPF_Initialize();
	
	/*
	功能名称:	释放资源
	函数名称:	OPF_Finalize
	输入参数:	
	输出参数:	
	返回值:   
	失败：
	功能描述:	重置全局变量，关闭P11_SESSION|OPEN_SSL
	*/
	COMMON_API unsigned int OPF_Finalize();

	/*
	功能名称:	导入证书
	函数名称:	OPF_CertImport
	输入参数:	aDevInfo        设备
				ain_value		证书内容
				ain_len			证书长度
	输出参数:	
	返回值:   
	失败：
	功能描述:	将证书导入到容器
	*/
	COMMON_API unsigned int OPF_CertImport(OPT_HCONTAINER hContainer, 
		const unsigned char * pbX509Cert, unsigned int uiX509CertLen);

	/*
	功能名称:	用现有SM2密钥对生成证书请求
	函数名称:	OPF_SM2GenCSR
	输入参数:	aHandle         容器句柄
				info			用户信息
	输出参数:	aout_value		证书内容
				aout_len		证书长度
	返回值:   
	失败：
	功能描述:	用现有SM2密钥对生成证书请求
	*/
	COMMON_API unsigned int OPF_SM2GenCSR(OPT_HCONTAINER hContainer,
		const OPST_USERINFO *pstUserInfo,unsigned char * pbCSR, unsigned int * puiCSRLen);

	/*
	功能名称:	签名证书请求
	函数名称:	OPF_SignCSR
	输入参数:	aHandle			私钥容器句柄
				ain_value_csr   请求值
				ain_len_csr		请求长度
	输出参数:	aout_value		签名内容
				aout_len		签名长度
				uiAlg			算法
	返回值:   
	失败：
	功能描述:	签名证书请求
	*/
	COMMON_API unsigned int OPF_SM2SignCSR(OPT_HCONTAINER hContainer,
		const unsigned char *pbCSR, unsigned int uiCSR,unsigned int uiAlg,
		unsigned char * pbCSRSigned, unsigned int * puiCSRSignedLen);

	/*
	功能名称:	签名证书
	函数名称:	OPF_SM2SignCert
	输入参数:	hSessionHandle			PCI句柄
				pbX509Cert   证书值
				uiX509CertLen	证书长度
				uiAlg			算法
	输出参数:	pbX509CertSigned		签名过后证书内容
				puiX509CertSignedLen		签名过后证书长度
	返回值:   
	失败：
	功能描述:	签名证书
	*/
	COMMON_API unsigned int OPF_SM2SignCert(void * hSessionHandle,
		const unsigned char *pbX509Cert, unsigned int uiX509CertLen,unsigned int uiAlg,
		unsigned char * pbX509CertSigned, unsigned int * puiX509CertSignedLen);

	/*
	功能名称:	签名CRL
	函数名称:	OPF_SM2SignCert
	输入参数:	hSessionHandle			PCI句柄
				pbX509Cert   						证书值
				uiX509CertLen						证书长度
				pbCRL										CRL内容
				uiCRL										CRL长度
				uiAlg									算法
	输出参数:	pbCRLSigned				签名过后CRL内容
				puiCRLSigned					签名过后CRL长度
	返回值:   
	失败：
	功能描述:	签名CRL
	*/
	COMMON_API unsigned int OPF_SM2SignCRL(void * hSessionHandle,
		const unsigned char *pbX509Cert, unsigned int uiX509CertLen,
		const unsigned char *pbCRL, unsigned int uiCRL,unsigned int uiAlg,
		unsigned char * pbCRLSigned, unsigned int * puiCRLSigned);


	// 二进制与HEX相互转换
	COMMON_API unsigned int OPF_Str2Bin(const char *pbIN,unsigned int uiIN,unsigned char *pbOUT,unsigned int * puiOUT);
	// 二进制与HEX相互转换
	COMMON_API unsigned int OPF_Bin2Str(const unsigned char *pbIN, unsigned int uiINLen, char *pbOUT, unsigned int * puiOUTLen);
		
		
#if defined(UNICODE)
#include <Windows.h>
	COMMON_API unsigned int OPF_WStr2Bin(const wchar_t *pbIN,unsigned int uiINLen,unsigned char *pbOUT,unsigned int * puiOUTLen);
	COMMON_API unsigned int OPF_Bin2WStr(const unsigned char *pbIN, unsigned int uiINLen, wchar_t *pbOUT, unsigned int * puiOUTLen);
#endif		
		

	// 单向列表操作
	COMMON_API unsigned int OPF_AddMallocedHandleNodeDataToLink(OPST_HANDLE_NODE * * ppstHeader, void * pvNodeData);
	COMMON_API unsigned int OPF_DelAndFreeHandleNodeDataFromLink(OPST_HANDLE_NODE * * ppstHeader,  void * pvNodeData);
	COMMON_API unsigned int OPF_CheckExistHandleNodeDataFromLink(OPST_HANDLE_NODE * * ppstHeader,  void * pvNodeData);
	COMMON_API unsigned int OPF_ClearExistHandleNodeDataFromLink(OPST_HANDLE_NODE * * ppstHeader);

#ifdef __cplusplus
}
#endif

#endif/* end _O_ALL_FUNC_DEF_H_*/
