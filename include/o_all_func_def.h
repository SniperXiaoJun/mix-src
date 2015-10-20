
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
	COMMON_API unsigned long OPF_Initialize();
	
	/*
	功能名称:	释放资源
	函数名称:	OPF_Finalize
	输入参数:	
	输出参数:	
	返回值:   
	失败：
	功能描述:	重置全局变量，关闭P11_SESSION|OPEN_SSL
	*/
	COMMON_API unsigned long OPF_Finalize();

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
	COMMON_API unsigned long OPF_CertImport(OPT_HCONTAINER hContainer, 
		const unsigned char * pbX509Cert, unsigned long ulX509CertLen);

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
	COMMON_API unsigned long OPF_SM2GenCSR(OPT_HCONTAINER hContainer,
		const OPST_USERINFO *pstUserInfo,unsigned char * pbCSR, unsigned long * pulCSRLen);

	/*
	功能名称:	签名证书请求
	函数名称:	OPF_SignCSR
	输入参数:	aHandle			私钥容器句柄
				ain_value_csr   请求值
				ain_len_csr		请求长度
	输出参数:	aout_value		签名内容
				aout_len		签名长度
				ulAlg			算法
	返回值:   
	失败：
	功能描述:	签名证书请求
	*/
	COMMON_API unsigned long OPF_SM2SignCSR(OPT_HCONTAINER hContainer,
		const unsigned char *pbCSR, unsigned long ulCSR,unsigned long ulAlg,
		unsigned char * pbCSRSigned, unsigned long * pulCSRSignedLen);

	/*
	功能名称:	签名证书
	函数名称:	OPF_SM2SignCert
	输入参数:	hSessionHandle			PCI句柄
				pbX509Cert   证书值
				ulX509CertLen	证书长度
				ulAlg			算法
	输出参数:	pbX509CertSigned		签名过后证书内容
				pulX509CertSignedLen		签名过后证书长度
	返回值:   
	失败：
	功能描述:	签名证书
	*/
	COMMON_API unsigned long OPF_SM2SignCert(void * hSessionHandle,
		const unsigned char *pbX509Cert, unsigned long ulX509CertLen,unsigned long ulAlg,
		unsigned char * pbX509CertSigned, unsigned long * pulX509CertSignedLen);

	/*
	功能名称:	签名CRL
	函数名称:	OPF_SM2SignCert
	输入参数:	hSessionHandle			PCI句柄
				pbX509Cert   						证书值
				ulX509CertLen						证书长度
				pbCRL										CRL内容
				ulCRL										CRL长度
				ulAlg									算法
	输出参数:	pbCRLSigned				签名过后CRL内容
				pulCRLSigned					签名过后CRL长度
	返回值:   
	失败：
	功能描述:	签名CRL
	*/
	COMMON_API unsigned long OPF_SM2SignCRL(void * hSessionHandle,
		const unsigned char *pbX509Cert, unsigned long ulX509CertLen,
		const unsigned char *pbCRL, unsigned long ulCRL,unsigned long ulAlg,
		unsigned char * pbCRLSigned, unsigned long * pulCRLSigned);


	// 二进制与HEX相互转换
	COMMON_API unsigned long OPF_Str2Bin(const char *pbIN,unsigned long ulIN,unsigned char *pbOUT,unsigned long * pulOUT);
	// 二进制与HEX相互转换
	COMMON_API unsigned long OPF_Bin2Str(const unsigned char *ain_data_value,unsigned long ain_data_len,
		char *aout_data_value,unsigned long * aout_data_len);

	// 单向列表操作
	COMMON_API unsigned long OPF_AddMallocedHandleNodeDataToLink(OPST_HANDLE_NODE * * ppstHeader, void * pvNodeData);
	COMMON_API unsigned long OPF_DelAndFreeHandleNodeDataFromLink(OPST_HANDLE_NODE * * ppstHeader,  void * pvNodeData);
	COMMON_API unsigned long OPF_CheckExistHandleNodeDataFromLink(OPST_HANDLE_NODE * * ppstHeader,  void * pvNodeData);
	COMMON_API unsigned long OPF_ClearExistHandleNodeDataFromLink(OPST_HANDLE_NODE * * ppstHeader);

#ifdef __cplusplus
}
#endif

#endif/* end _O_ALL_FUNC_DEF_H_*/
