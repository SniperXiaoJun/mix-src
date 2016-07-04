




#ifndef _PKCS11_FUNC_DEF_H_
#define _PKCS11_FUNC_DEF_H_

#include "common.h"
#include "o_all_type_def.h"

#ifdef __cplusplus
extern "C" {
#endif
	/*
	功能名称:	初始化资源
	函数名称:	PKCS11_Initialize
	输入参数:	
	输出参数:	
	返回值:   
	失败：
	功能描述:	初始化PKCS11
	*/
	COMMON_API unsigned long PKCS11_Initialize();

	/*
	功能名称:	释放资源
	函数名称:	PKCS11_Finalize
	输入参数:	
	输出参数:	
	返回值:   
	失败：
	功能描述:	释放资源
	*/
	COMMON_API unsigned long PKCS11_Finalize();

	/*
	功能名称:	枚举设备
	函数名称:	PKCS11_EnumDevices
	输入参数:	pszDevicesInfo			设备个数
				pulDevCount		设备信息
	输出参数:	pszDevicesInfo		设备信息
				pulDevCount			设备个数
	返回值:   
	失败：
	功能描述:	枚举并记录当前设备
	*/
	COMMON_API unsigned long PKCS11_EnumDevices(OPST_DEV pszDevicesInfo[], unsigned long * pulDevCount);

	/*
	功能名称:	打开设备
	函数名称:	PKCS11_OpenDevice
	输入参数:	stDeviceInfo			设备信息
	输出参数:	hHandleDev			设备句柄
	返回值:   
	失败：
	功能描述:	打开设备
	*/
	COMMON_API unsigned long PKCS11_OpenDevice(OPST_DEV stDeviceInfo,OPT_HDEVICE * phHandleDev);

	/*
	功能名称:	关闭设备
	函数名称:	PKCS11_CloseDevice
	输入参数:	hHandleDev			设备句柄
	输出参数:	
	返回值:   
	失败：
	功能描述:	关闭设备
	*/
	COMMON_API unsigned long PKCS11_CloseDevice(OPT_HDEVICE hHandleDev);

	/*
	功能名称:	登录设备
	函数名称:	PKCS11_Login
	输入参数:	hHandleDev		设备句柄
				ulLoginType		用户类型 0:管理员 1:用户
				pbPin			口令值
				ulPinLen		口令长度
	输出参数:	pulRetryTimes	重试次数
	返回值:   
	失败：
	功能描述:	登录当前设备
	*/
	COMMON_API unsigned long PKCS11_Login(OPT_HDEVICE hHandleDev, unsigned long ulLoginType,
		const unsigned char*pbPin, unsigned long ulPinLen, unsigned long *pulRetryTimes);

	/*
	功能名称:	注销登录设备
	函数名称:	PKCS11_Logout
	输入参数:	hHandleDev		设备句柄
	输出参数:	
	返回值:   
	失败：
	功能描述:	注销登录当前设备
	*/
	COMMON_API unsigned long PKCS11_Logout(OPT_HDEVICE hHandleDev);

	/*
	功能名称:	创建容器
	函数名称:	PKCS11_CreateContainer
	输入参数:	hHandleDev		设备句柄
				pbConNameValue	容器名称
				ulConNameLen		容器名称长度
	输出参数:	
	返回值:   
	失败：
	功能描述:	创建容器
	*/
	COMMON_API unsigned long PKCS11_CreateContainer(OPT_HDEVICE hHandleDev,
		const unsigned char * pbConNameValue, unsigned long ulConNameLen);

	/*
	功能名称:	删除容器
	函数名称:	PKCS11_DeleteContainer
	输入参数:	hHandleDev		设备句柄
				pbConNameValue	容器名称
				ulConNameLen		容器名称长度
	输出参数:	
	返回值:   
	失败：
	功能描述:	删除容器
	*/
	COMMON_API unsigned long PKCS11_DeleteContainer(OPT_HDEVICE hHandleDev, 
		const unsigned char * pbConNameValue, unsigned long ulConNameLen);

	/*
	功能名称:	枚举容器
	函数名称:	PKCS11_EnumContainers
	输入参数:	hHandleDev		设备句柄
				pulConCount		容器个数
				pszContainers     容器结构体数组
	输出参数:	pulConCount		容器个数
				pszContainers     容器结构体数组（包含容器名称和长度）
	返回值:   
	失败：
	功能描述:	枚举容器
	*/
	COMMON_API unsigned long PKCS11_EnumContainers(OPT_HDEVICE hHandleDev, OPST_CONTAINER pszContainers[], 
		unsigned long * pulConCount);

	/*
	功能名称:	检测容器是否存在
	函数名称:	PKCS11_CheckContainerExist
	输入参数:	hHandleDev		设备句柄
				pbConNameValue	容器名称		（OPST_CONTAINER 结构体包含容器名和长度）
				ulConNameLen		容器名长度		（OPST_CONTAINER 结构体包含容器名和长度）
	输出参数:	
	返回值:   
	失败：
	功能描述:	检测容器是否存在
	*/
	COMMON_API unsigned long PKCS11_CheckContainerExist(OPT_HDEVICE hHandleDev, 
		const unsigned char * pbConNameValue, unsigned long ulConNameLen);

	/*
	功能名称:	打开容器
	函数名称:	PKCS11_OpenContainer
	输入参数:	hHandleDev		设备句柄
				pbConNameValue	容器名称		（OPST_CONTAINER 结构体包含容器名和长度）
				ulConNameLen		容器名长度		（OPST_CONTAINER 结构体包含容器名和长度）
				ulConType		密钥类型 加密:0  签名:1
	输出参数:	
				phHandleCon			容器句柄
	返回值:   
	失败：
	功能描述:	打开容器
	*/
	COMMON_API unsigned long PKCS11_OpenContainer(OPT_HDEVICE hHandleDev,const unsigned char * pbConNameValue, 
		unsigned long ulConNameLen,unsigned long ulConType, OPT_HCONTAINER * phHandleCon);

	/*
	功能名称:	关闭容器
	函数名称:	PKCS11_CloseContainer
	输入参数:	hHandle			容器句柄
	输出参数:	
	返回值:   
	失败：
	功能描述:	关闭容器
	*/
	COMMON_API unsigned long PKCS11_CloseContainer(OPT_HCONTAINER hHandle);

	/*
	功能名称:	生成SM2公私钥对
	函数名称:	PKCS11_SM2GenKeys
	输入参数:	hHandle        容器句柄
	输出参数:	
	返回值:   
	失败：
	功能描述:	生成SM2密钥对（P11）
	*/
	COMMON_API unsigned long PKCS11_SM2GenKeys(OPT_HCONTAINER hHandle);

	/*
	功能名称:	导出公钥
	函数名称:	PKCS11_SM2ExportKeys
	输入参数:	hHandle         容器句柄
	输出参数:	pbPubKeyX		公钥X值
				pulPubKeyLenX		公钥X长度
				pbPubKeyY		公钥Y值
				pulPubKeyLenY		公钥Y长度
	返回值:   
	失败：
	功能描述:	导出公钥
	*/
	COMMON_API unsigned long PKCS11_SM2ExportKeys(OPT_HCONTAINER hHandle,
		unsigned char *pbPubKeyX, unsigned long *pulPubKeyLenX, unsigned char *pbPubKeyY, 
		unsigned long *pulPubKeyLenY);

	/*
	功能名称:	导入SM2公私钥对
	函数名称:	PKCS11_SM2ImportKeys
	输入参数:	hHandle			容器句柄
				ulHandleEnDecypt 加解密容器句柄
				pbPrvkey	私钥值
				ulPrvKeyLen		私钥长度
				pbPubkeyX		公钥X值
				ulPubkeyXLen		公钥X长度
				pbPubkeyY		公钥Y值
				ulPubkeyYLen		公钥Y长度
	输出参数:	
	返回值:   
	失败：
	功能描述:	将SM2公私钥导入到容器
	*/
	COMMON_API unsigned long PKCS11_SM2ImportKeys(OPT_HCONTAINER hHandle,OPT_HCONTAINER ulHandleEnDecypt, 
		const unsigned char * pbPrvkey, unsigned long ulPrvKeyLen, 
		const unsigned char * pbPubkeyX, unsigned long ulPubkeyXLen, 
		const unsigned char * pbPubkeyY, unsigned long ulPubkeyYLen);


	/*
	功能名称:	导入证书
	函数名称:	PKCS11_CertImport
	输入参数:	hHandle				容器句柄
				pbCert			证书内容
				ulCertLen				证书长度
				pbSubject	主题内容
				ulSubjectLen		主题长度
	输出参数:	
	返回值:   
	失败：
	功能描述:	将证书导入到容器
	*/
	COMMON_API unsigned long PKCS11_CertImport(OPT_HCONTAINER hHandle,
		const unsigned char * pbCert, unsigned long ulCertLen,
		const unsigned char * pbSubject, unsigned long ulSubjectLen);

	/*
	功能名称:	导出证书
	函数名称:	PKCS11_CertExport
	输入参数:	hHandle			容器句柄
	输出参数:	pbCert		证书内容
				pulCertLen		证书长度
	返回值:   
	失败：
	功能描述:	将证书从容器导出
	*/
	COMMON_API unsigned long PKCS11_CertExport(OPT_HCONTAINER hHandle, unsigned char * pbCert, unsigned long * pulCertLen);

	/*
	功能名称:	签名消息
	函数名称:	PKCS11_SignMSG
	输入参数:	hHandle			容器句柄
				pbIn		原文值
				ulInLen			原文长度
				ulAlg			算法
	输出参数:	pbSigValue		签名内容
				pulSigLen		签名长度
	返回值:   
	失败：
	功能描述:	签名消息
	*/
	COMMON_API unsigned long PKCS11_SM2SignMSG(OPT_HCONTAINER hHandle,
		const unsigned char *pbIn, unsigned long ulInLen,unsigned long ulAlg,
		unsigned char * pbSigValue, unsigned long * pulSigLen);


	/*
	功能名称:	验证消息
	函数名称:	PKCS11_VerifyMSG
	输入参数:	hHandle			容器句柄
				pbMsg		原文值
				ulMsgLen		原文长度
				ulAlg			算法
				pbSigValue		签名内容
				ulSigLen		签名长度
	输出参数:
	返回值:   
	失败：
	功能描述:	验证消息
	*/
	COMMON_API unsigned long PKCS11_SM2VerifyMSG(OPT_HCONTAINER hHandle,
		const unsigned char *pbMsg, unsigned long ulMsgLen,unsigned long ulAlg,
		const unsigned char *pbSigValue, unsigned long ulSigLen );

#ifdef __cplusplus
}
#endif




#endif/*_PKCS11_FUNC_DEF_H_*/


