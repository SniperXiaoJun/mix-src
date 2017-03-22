
#ifndef __RT_P11_API__H_
#define __RT_P11_API__H_



//defines

#define RT_SM2_CON_NAME                                   "RT_SM_CON"
#define RT_SM2_CON_NAME_SIGN                              "RT_SM_CON-Sign"
#define RT_SM2_CON_NAME_CRYPT                             "RT_SM_CON-enc"
#define RT_SECID                                          "RT_SECID"
#define RT_HMAC_KEY                                       "RT_HMAC_KEY"
#define RT_ZM_SIGN                                        "RT_ZM_SIGN"
#define RT_ZM_ENC                                         "RT_ZM_ENC"
#define RT_ZM_EXC                                         "RT_ZM_EXC"
#define RT_ZM_KPX                                         "RT_ZM_KPX"
#define RT_ZM_ZMP                                         "RT_ZM_ZMP"


#ifdef __cplusplus
extern "C" {
#endif

	int RT_P11_API_SetMetas(
		unsigned char *pTarget, int uiTargetLen,
		unsigned char *pSecID, int uiSecIDLen,
		unsigned char *pHMac, int uiHMacLen
		);
	
	int RT_P11_API_SetZMMetas(
		unsigned char *pTarget, int uiTargetLen,
		unsigned char *pZMP, int uiZMPLen
		unsigned char *pSignKey, int uiSignKeyLen,
		unsigned char *pCryptKey, int uiCryptKeyLen,
		unsigned char *pExchangeKey, int uiExchangeKeyLen
		);
		
	int RT_P11_API_SetZMCerts(
		unsigned char *pTarget, int uiTargetLen,
		unsigned char *pSignCert, int uiSignCertLen,
		unsigned char *pCryptCert, int uiCryptCertLen,
		unsigned char *pExchangeCert, int uiExchangeCertLen
		);

#ifdef __cplusplus
}
#endif


#endif