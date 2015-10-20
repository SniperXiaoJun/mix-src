





#ifndef _KMS_CAPI_H

#define _KMS_CAPI_H

#include "o_all_type_def.h"
#include <Windows.h>
#include "SKFInterface.h"
#include "SKFError.h"

#ifdef __cplusplus
extern "C"
{
#endif
	// 设置初始化PIN
	unsigned int CAPI_KEY_SetPin(char * pszKeyOn,int ulKeyTarget, char * pszPINAdmin,char * pszPINUser);

	// 解锁用户密码
	unsigned int CAPI_KEY_UnlockPin(char * pszKeyOn,int ulKeyTarget, char * pszPINAdmin,char * pszPINUser, unsigned int * pulRetry);
	// 设置Key类型
	unsigned int CAPI_KEY_SetMeta(char * pszKeyOn, int ulKeyTarget,OPT_ST_USB_META * pMeta, char * pszPIN, unsigned int * pulRetry);
	// 生成密钥对
	unsigned int CAPI_KEY_GenKeyPair(char * pszKeyOn,int ulKeyTarget, char * pszPIN, unsigned int * pulRetry);
	// 数据签名
	unsigned int CAPI_KEY_SignDigest(char * pszKeyOn,int ulKeyTarget, char * pszPIN, unsigned char *pbDigest, unsigned char * pbSigValue, unsigned int * pulRetry);
	// 导出公钥
	unsigned int CAPI_KEY_ExportPK(char * pszKeyOn,int ulKeyTarget,unsigned int bIsSign, unsigned char * pbPK);
	// 导入密钥对
	unsigned int CAPI_KEY_ImportKeyPair(char * pszKeyOn,int ulKeyTarget, unsigned char * pbKeyPair, char * pszPIN, unsigned int * pulRetry);
	// 导入证书
	unsigned int CAPI_KEY_ImportCert(char * pszKeyOn,int ulKeyTarget, unsigned int bIsSign,unsigned char * pbCert,unsigned int ulCertLen, char * pszPIN, unsigned int * pulRetry);
	// 获取Key类型
	unsigned int CAPI_KEY_GetMeta(char * pszKeyOn, int ulKeyTarget, OPT_ST_USB_META * pMeta);
	// 检测目标Key是否存在
	unsigned int CAPI_KEY_CheckOnOff(char * pszKeyOn,int ulKeyTarget, OPT_ST_USB_META * pstMeta);
	// 解锁Key
	unsigned int CAPI_KEY_UnlockWeb(char * pszKeyOn,int ulKeyTarget, OPT_ST_USB_META * pstMeta,char * pszPIN,unsigned int * pulRetry);
	// 检测目标Key的安全状态（解决是否 要再次输入密码）
	unsigned int CAPI_KEY_SecureState(char * pszKeyOn,int ulKeyTarget, OPT_ST_USB_META * pstMeta);
	// 获取设备信息
	unsigned int CAPI_KEY_GetInfo(/*IN OUT*/char * pszKeyOn, int ulKeyTarget,DEVINFO * pInfo);

	// 删除所有应用
	unsigned int CAPI_KEY_ClearApp(/*IN OUT*/char * pszKeyOn, int ulKeyTarget);

	unsigned int CAPI_KEY_SetStr(char * strIN);

	unsigned int CAPI_KEY_GetStr(char * strOut);

#ifdef __cplusplus
}
#endif


#endif