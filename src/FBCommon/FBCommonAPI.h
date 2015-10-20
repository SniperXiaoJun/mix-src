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
	void InitArgsUserInfo(FB::VariantList aArrayArgIN);
	// ����ǩ����Կ��
	void InitArgsSKFSetUserPIN(FB::VariantList aArrayArgIN);
	void InitArgsSKFSetUserPINAndValidCode(FB::VariantList variantList);
	// ��ʼ�����������ŷ�
	void InitArgsSKFImportSM2KeyPair(FB::VariantList aArrayArgIN);
	void InitArgsSKFImportCerts(FB::VariantList variantList);
	void InitArgsSKFSetUserPINAndUserInfo(FB::VariantList variantList);
	void InitArgsShowCert(FB::VariantList variantList);

	bool get_isrun();
   
	unsigned int get_ulResult();
	unsigned int get_ulRetry();

	std::string get_PublicKeySIGN();

	std::string get_signed_csr();

	std::string get_PublicKeyEX();

	std::string get_testString();

	std::string get_authKey();
	std::string get_authKeyName();
	unsigned long get_authKeyType();
	std::string get_sigValue();

	std::string get_sn();

    void set_testString(const std::string& val);

    std::string get_version();

	// Event helpers
	FB_JSAPI_EVENT(usbevent, 2, (const FB::variant&, const int));

	FB_JSAPI_EVENT(usbeventonoff, 2, (const FB::variant&, const int));

	unsigned long ulResult;
	unsigned int m_ulRetry;

	// δǩ���ĵ�֤������
	unsigned char m_szCsr[BUFFER_LEN_1K * 4]; 
	unsigned long m_iCsrLen;
	unsigned char m_szSigValue[BUFFER_LEN_1K]; 
	
	// ǩ���ĵ�֤������
	unsigned char m_szSignedCsr[BUFFER_LEN_1K * 4]; 
	unsigned long m_iSignedCsrLen;

	HANDLE hThrd; // �߳̾��
	DWORD threadId;
	char m_szPIN[BUFFER_LEN_1K];
	int m_iPINLen;

	char m_szValidCode[BUFFER_LEN_1K];
	int m_iValidCodeLen;

	int ulContype;
	OPST_USERINFO userInfo;

	////////////////////////////////////////////////////////////////////////
	// �汾2�ù��ܽӿ�
	unsigned char m_szPublicKeySIGN[SM2_BYTES_LEN * 2]; // ǩ����Կ
	unsigned char m_szPublicKeyEX[SM2_BYTES_LEN * 2];	// ������Կ
	OPST_SKF_ENVELOPEDKEYBLOB m_stEnvelopedKeyBlobEX;   // ������Կ�����ŷ�

	// ǩ���ĵ�֤������
	unsigned char m_szSKFCsrSIGN[BUFFER_LEN_1K * 4]; 
	unsigned long m_iSKFCsrSIGNLen;

	// ǩ��֤��
	unsigned char m_szCertSIGN[BUFFER_LEN_1K * 4]; 
	unsigned long m_iCertSIGNLen;

	// Ҫ��ʾ��֤��
	unsigned char m_szCertShow[BUFFER_LEN_1K * 4]; 
	unsigned long m_iCertShowLen;

	// ����֤��
	unsigned char m_szCertEX[BUFFER_LEN_1K * 4]; 
	unsigned long m_iCertEXLen;

	// ��֤KEY
	static OPT_ST_USB_META m_stMetaAuth;
	// ֤��KEY
	static OPT_ST_USB_META m_stMetaCert;
	// ������ӵ�KEY
	static OPT_ST_USB_META m_stMetaAuthAdd;

	// ��֤KEY����¼KEY��
	static char m_szAuthKey[BUFFER_LEN_1K]; 

private:
    FBCommonWeakPtr m_plugin;
    FB::BrowserHostPtr m_host;

	DEVINFO m_devInfo;
	
	std::string m_randomAdminPin;

    std::string m_testString;
};

#endif // H_FBCommonAPI

