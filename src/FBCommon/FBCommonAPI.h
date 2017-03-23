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

	// ��ʼ��֤����������Ϣ
	void InitArgsUserInfo(FB::VariantList variantList);
	// �����û�����
	void InitArgsSKFSetUserPIN(FB::VariantList variantList);
	void InitArgsSKFSetUserPINAndValidCode(FB::VariantList variantList);
	// ��ʼ�����������ŷ�


	void InitArgsSKFImportSM2KeyPair(FB::VariantList variantList);
	void InitArgsSKFImportSM2Certs(FB::VariantList variantList);
	void InitArgsSKFSetUserPINAndUserInfo(FB::VariantList variantList);

#if defined(GM_ECC_512_SUPPORT)
	void InitArgsSKFImportECC512KeyPair(FB::VariantList variantList);
	void InitArgsSKFImportECC512Certs(FB::VariantList variantList);


	// ECC512δǩ���ĵ�֤������
	unsigned char m_szCsrECC512[BUFFER_LEN_1K * 4]; 
	unsigned int m_iCsrLenECC512;

	// ECC512ǩ���ĵ�֤������
	unsigned char m_szSignedCsrECC512[BUFFER_LEN_1K * 4]; 
	unsigned int m_iSignedCsrLenECC512;

	////////////////////////////////////////////////////////////////////////
	// �汾ECC512�ù��ܽӿ�
	unsigned char m_szPublicKeySIGNECC512[64 * 2];  // ǩ����Կ
	unsigned char m_szPublicKeyENECC512[64 * 2];	// ���ܹ�Կ
	unsigned char m_szPublicKeyEXECC512[64 * 2];	// ������Կ

	OPST_SKF_ENVELOPEDKEYBLOB m_stEnvelopedKeyBlobEXECC512;   // ������Կ�����ŷ�
	OPST_SKF_ENVELOPEDKEYBLOB m_stEnvelopedKeyBlobENECC512;   // ������Կ�����ŷ�

	// ECC512ǩ��֤��
	unsigned char m_szCertSIGNECC512[BUFFER_LEN_1K * 4]; 
	unsigned int m_iCertSIGNLenECC512;

	// ECC512����֤��
	unsigned char m_szCertEXECC512[BUFFER_LEN_1K * 4]; 
	unsigned int m_iCertEXLenECC512; 

	// ECC512����֤��
	unsigned char m_szCertENECC512[BUFFER_LEN_1K * 4]; 
	unsigned int m_iCertENLenECC512; 

	std::string get_signed_csrECC512();
	std::string get_PublicKeyENECC512();
	std::string get_PublicKeyEXECC512();
	std::string get_PublicKeySIGNECC512();

	unsigned int ulKeyState;

	unsigned int get_ulKeyState();
#elif defined(GM_ECC_512_SUPPORT_RT)
	// ECC512ǩ��֤��
	unsigned char m_szCertSIGNECC512[BUFFER_LEN_1K * 4]; 
	unsigned int m_iCertSIGNLenECC512;

	// ECC512����֤��
	unsigned char m_szCertEXECC512[BUFFER_LEN_1K * 4]; 
	unsigned int m_iCertEXLenECC512; 

	// ECC512����֤��
	unsigned char m_szCertENECC512[BUFFER_LEN_1K * 4]; 
	unsigned int m_iCertENLenECC512; 

	unsigned int ulKeyState;
	unsigned int get_ulKeyState();

	void InitArgsECC512ZMMetas(FB::VariantList variantList);
	void InitArgsECC512Certs(FB::VariantList variantList);
	void InitArgsECC512Metas(FB::VariantList variantList);

	unsigned char m_szKeySignECC512[4 + 2*64 + 4 + 64];  // ǩ����Կ�� 4 + 2*64 + 4 + 64
	unsigned char m_szKeyEnECC512[4 + 2*64 + 4 + 64];	 // ������Կ��
	unsigned char m_szKeyExECC512[4 + 2*64 + 4 + 64];	 // ������Կ��
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

	// ��֤��ǩ��(�м�ֵǩ��)
	std::string get_sigValue();

	// ��ȡ���к�
	std::string get_sn();
	// ��д����Ա����
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

	// δǩ���ĵ�֤������
	unsigned char m_szCsr[BUFFER_LEN_1K * 4]; 
	unsigned int m_iCsrLen;
	unsigned char m_szSigValue[BUFFER_LEN_1K]; 
	
	// ǩ���ĵ�֤������
	unsigned char m_szSignedCsr[BUFFER_LEN_1K * 4]; 
	unsigned int m_iSignedCsrLen;

	HANDLE hThrd; // �߳̾��
	DWORD threadId;
	char m_szPIN[64];
	int m_iPINLen;

	char m_szValidCode[10];
	int m_iValidCodeLen;

	int ulContype;
	OPST_USERINFO userInfo;

	////////////////////////////////////////////////////////////////////////
	// �汾2�ù��ܽӿ�
	unsigned char m_szPublicKeySIGN[SM2_BYTES_LEN * 2]; // ǩ����Կ
	unsigned char m_szPublicKeyEX[SM2_BYTES_LEN * 2];	// ������Կ
	OPST_SKF_ENVELOPEDKEYBLOB m_stEnvelopedKeyBlobEX;   // ������Կ�����ŷ�

	// ǩ��֤��
	unsigned char m_szCertSIGN[BUFFER_LEN_1K * 4]; 
	unsigned int m_iCertSIGNLen;

	// Ҫ��ʾ��֤��
	unsigned char m_szCertShow[BUFFER_LEN_1K * 4]; 
	unsigned int m_iCertShowLen;

	// ����֤��
	unsigned char m_szCertEX[BUFFER_LEN_1K * 4]; 
	unsigned int m_iCertEXLen;

	// ��֤KEY
	static OPT_ST_USB_META m_stMetaAuth;
	// ֤��KEY
	static OPT_ST_USB_META m_stMetaCert;
	// ������ӵ�KEY
	static OPT_ST_USB_META m_stMetaAuthAdd;

	// ��֤KEY����¼KEY��
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

