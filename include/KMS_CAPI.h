





#ifndef _KMS_CAPI_H

#define _KMS_CAPI_H

#include "o_all_type_def.h"

#ifdef __cplusplus
extern "C"
{
#endif
	// ���ó�ʼ��PIN
	unsigned int CAPI_KEY_SetPin(char * pszKeyOn,int ulKeyTarget, char * pszPINAdmin,char * pszPINUser);
	// ����Key����
	unsigned int CAPI_KEY_SetMeta(char * pszKeyOn, int ulKeyTarget,OPT_ST_USB_META * pMeta, char * pszPIN, unsigned int * pulRetry);
	// ������Կ��
	unsigned int CAPI_KEY_GenKeyPair(char * pszKeyOn,int ulKeyTarget, char * pszPIN, unsigned int * pulRetry);
	// ����ǩ��
	unsigned int CAPI_KEY_SignDigest(char * pszKeyOn,int ulKeyTarget, char * pszPIN, unsigned char *pbDigest, unsigned char * pbSigValue, unsigned int * pulRetry);
	// ������Կ
	unsigned int CAPI_KEY_ExportPK(char * pszKeyOn,int ulKeyTarget,unsigned int bIsSign, unsigned char * pbPK);
	// ������Կ��
	unsigned int CAPI_KEY_ImportKeyPair(char * pszKeyOn,int ulKeyTarget, unsigned char * pbKeyPair, char * pszPIN, unsigned int * pulRetry);
	// ����֤��
	unsigned int CAPI_KEY_ImportCert(char * pszKeyOn,int ulKeyTarget, unsigned int bIsSign,unsigned char * pbCert,unsigned int ulCertLen, char * pszPIN, unsigned int * pulRetry);
	// ��ȡKey����
	unsigned int CAPI_KEY_GetMeta(char * pszKeyOn, int ulKeyTarget, OPT_ST_USB_META * pMeta);
	// ���Ŀ��Key�Ƿ����
	unsigned int CAPI_KEY_CheckOnOff(char * pszKeyOn,int ulKeyTarget, OPT_ST_USB_META * pstMeta);
	// ����Key
	unsigned int CAPI_KEY_Unlock(char * pszKeyOn,int ulKeyTarget, OPT_ST_USB_META * pstMeta,char * pszPIN,unsigned int * pulRetry);
	// ���Ŀ��Key�İ�ȫ״̬������Ƿ� Ҫ�ٴ��������룩
	unsigned int CAPI_KEY_SecureState(char * pszKeyOn,int ulKeyTarget, OPT_ST_USB_META * pstMeta);


	unsigned int CAPI_KEY_SetStr(char * strIN);

	unsigned int CAPI_KEY_GetStr(char * strOut);


#ifdef __cplusplus
}
#endif


#endif