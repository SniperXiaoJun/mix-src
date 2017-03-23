/**********************************************************\

  Auto-generated FBCommonAPI.h

\**********************************************************/

#include <string>
#include <sstream>
#include <boost/weak_ptr.hpp>
#include "JSAPIAuto.h"
#include "BrowserHost.h"
#include "FBCommon.h"
#include "Windows.h"
#include "o_all_type_def.h"
#include "SKFInterface.h"

#ifndef H_FBCommonAPI
#define H_FBCommonAPI

class FBCommonAPI : public FB::JSAPIAuto
{
public:
    ////////////////////////////////////////////////////////////////////////////
    /// @fn FBCommonAPI::FBCommonAPI(const FBCommonPtr& plugin, const FB::BrowserHostPtr host)
    ///
    /// @brief  Constructor for your JSAPI object.
    ///         You should register your methods, properties, and events
    ///         that should be accessible to Javascript from here.
    ///
    /// @see FB::JSAPIAuto::registerMethod
    /// @see FB::JSAPIAuto::registerProperty
    /// @see FB::JSAPIAuto::registerEvent
    ////////////////////////////////////////////////////////////////////////////
    FBCommonAPI(const FBCommonPtr& plugin, const FB::BrowserHostPtr& host);

    ///////////////////////////////////////////////////////////////////////////////
    /// @fn FBCommonAPI::~FBCommonAPI()
    ///
    /// @brief  Destructor.  Remember that this object will not be released until
    ///         the browser is done with it; this will almost definitely be after
    ///         the plugin is released.
    ///////////////////////////////////////////////////////////////////////////////
    virtual ~FBCommonAPI();

    FBCommonPtr getPlugin();

	void ExecCommonFuncID(long aFuncID, FB::VariantList aArrayArgIN, FB::VariantList aArrayArgOUT);

	// 初始化证书申请者信息
	void InitArgsUserInfo(FB::VariantList variantList);
	// 设置用户密码
	void InitArgsSKFSetUserPIN(FB::VariantList variantList);
	void InitArgsSKFSetUserPINAndValidCode(FB::VariantList variantList);
	// 初始化交换数字信封


	void InitArgsSKFImportSM2KeyPair(FB::VariantList variantList);
	void InitArgsSKFImportSM2Certs(FB::VariantList variantList);
	void InitArgsSKFSetUserPINAndUserInfo(FB::VariantList variantList);

#if defined(GM_ECC_512_SUPPORT)
	void InitArgsSKFImportECC512KeyPair(FB::VariantList variantList);
	void InitArgsSKFImportECC512Certs(FB::VariantList variantList);


	// ECC512未签名的的证书请求
	unsigned char m_szCsrECC512[BUFFER_LEN_1K * 4]; 
	unsigned int m_iCsrLenECC512;

	// ECC512签名的的证书请求
	unsigned char m_szSignedCsrECC512[BUFFER_LEN_1K * 4]; 
	unsigned int m_iSignedCsrLenECC512;

	////////////////////////////////////////////////////////////////////////
	// 版本ECC512用国密接口
	unsigned char m_szPublicKeySIGNECC512[64 * 2];  // 签名公钥
	unsigned char m_szPublicKeyENECC512[64 * 2];	// 加密公钥
	unsigned char m_szPublicKeyEXECC512[64 * 2];	// 交换公钥

	OPST_SKF_ENVELOPEDKEYBLOB m_stEnvelopedKeyBlobEXECC512;   // 交换密钥数字信封
	OPST_SKF_ENVELOPEDKEYBLOB m_stEnvelopedKeyBlobENECC512;   // 加密密钥数字信封

	// ECC512签名证书
	unsigned char m_szCertSIGNECC512[BUFFER_LEN_1K * 4]; 
	unsigned int m_iCertSIGNLenECC512;

	// ECC512交换证书
	unsigned char m_szCertEXECC512[BUFFER_LEN_1K * 4]; 
	unsigned int m_iCertEXLenECC512; 

	// ECC512加密证书
	unsigned char m_szCertENECC512[BUFFER_LEN_1K * 4]; 
	unsigned int m_iCertENLenECC512; 

	std::string get_signed_csrECC512();
	std::string get_PublicKeyENECC512();
	std::string get_PublicKeyEXECC512();
	std::string get_PublicKeySIGNECC512();

	unsigned int ulKeyState;

	unsigned int get_ulKeyState();
#elif defined(GM_ECC_512_SUPPORT_RT)
	// ECC512签名证书
	unsigned char m_szCertSIGNECC512[BUFFER_LEN_1K * 4]; 
	unsigned int m_iCertSIGNLenECC512;

	// ECC512交换证书
	unsigned char m_szCertEXECC512[BUFFER_LEN_1K * 4]; 
	unsigned int m_iCertEXLenECC512; 

	// ECC512加密证书
	unsigned char m_szCertENECC512[BUFFER_LEN_1K * 4]; 
	unsigned int m_iCertENLenECC512; 

	unsigned int ulKeyState;
	unsigned int get_ulKeyState();

	void InitArgsECC512ZMMetas(FB::VariantList variantList);
	void InitArgsECC512Certs(FB::VariantList variantList);
	void InitArgsECC512Metas(FB::VariantList variantList);

	unsigned char m_szKeySignECC512[4 + 2*64 + 4 + 64];  // 签名密钥对 4 + 2*64 + 4 + 64
	unsigned char m_szKeyEnECC512[4 + 2*64 + 4 + 64];	 // 加密密钥对
	unsigned char m_szKeyExECC512[4 + 2*64 + 4 + 64];	 // 交换密钥对
	unsigned char m_szR1[32];
	unsigned char m_szR2[32];
	unsigned char m_szHMac[32*9];
	unsigned char m_szZMP[32*3];
	char m_szSecID[32];
#endif


	void InitArgsShowCert(FB::VariantList variantList);

	bool get_isrun();
   
	unsigned int get_ulResult();
	unsigned int get_ulRetry();

	unsigned int get_keyCount();

	std::string get_PublicKeySIGN();
	std::string get_signed_csr();
	std::string get_PublicKeyEX();

	std::string get_testString();

	std::string get_authKey();
	std::string get_authKeyName();
	unsigned int get_authKeyType();

	// 验证码签名(中间值签名)
	std::string get_sigValue();

	// 获取序列号
	std::string get_sn();
	// 读写管理员密码
	void set_adminPin(const std::string& val);
	std::string get_adminPin();

	void set_oldPin(const std::string& val);
	void set_newPin(const std::string& val);
	std::string get_newPin();
	std::string get_oldPin();


    std::string get_version();

	// Event helpers
	FB_JSAPI_EVENT(usbevent, 2, (const FB::variant&, const int));
	FB_JSAPI_EVENT(usbeventonoff, 2, (const FB::variant&, const int));

	unsigned int ulResult;
	unsigned int m_ulRetry;

	// 未签名的的证书请求
	unsigned char m_szCsr[BUFFER_LEN_1K * 4]; 
	unsigned int m_iCsrLen;
	unsigned char m_szSigValue[BUFFER_LEN_1K]; 
	
	// 签名的的证书请求
	unsigned char m_szSignedCsr[BUFFER_LEN_1K * 4]; 
	unsigned int m_iSignedCsrLen;

	HANDLE hThrd; // 线程句柄
	DWORD threadId;
	char m_szPIN[64];
	int m_iPINLen;

	char m_szValidCode[10];
	int m_iValidCodeLen;

	int ulContype;
	OPST_USERINFO userInfo;

	////////////////////////////////////////////////////////////////////////
	// 版本2用国密接口
	unsigned char m_szPublicKeySIGN[SM2_BYTES_LEN * 2]; // 签名公钥
	unsigned char m_szPublicKeyEX[SM2_BYTES_LEN * 2];	// 交换公钥
	OPST_SKF_ENVELOPEDKEYBLOB m_stEnvelopedKeyBlobEX;   // 交换密钥数字信封

	// 签名证书
	unsigned char m_szCertSIGN[BUFFER_LEN_1K * 4]; 
	unsigned int m_iCertSIGNLen;

	// 要显示的证书
	unsigned char m_szCertShow[BUFFER_LEN_1K * 4]; 
	unsigned int m_iCertShowLen;

	// 交换证书
	unsigned char m_szCertEX[BUFFER_LEN_1K * 4]; 
	unsigned int m_iCertEXLen;

	// 认证KEY
	static OPT_ST_USB_META m_stMetaAuth;
	// 证书KEY
	static OPT_ST_USB_META m_stMetaCert;
	// 即将添加的KEY
	static OPT_ST_USB_META m_stMetaAuthAdd;

	// 认证KEY（登录KEY）
	static char m_szAuthKey[BUFFER_LEN_1K]; 

	static int m_iKeyCount; 

private:
    FBCommonWeakPtr m_plugin;
    FB::BrowserHostPtr m_host;

	DEVINFO m_devInfo;
	
	std::string m_AdminPin;
	std::string m_OldPin;
	std::string m_NewPin;
};

#endif // H_FBCommonAPI

