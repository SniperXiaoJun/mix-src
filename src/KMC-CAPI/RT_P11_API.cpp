#include "RT_P11_API.h"
#include "FILE_LOG.h"
#include "o_all_type_def.h"
#include "o_all_func_def.h"
#include <string.h>
#include <pkcs11/cryptoki-win32.h>

CK_BBOOL True = CK_TRUE;
CK_BBOOL bFalse = CK_FALSE;

HMODULE g_hP11Module = NULL;
CK_FUNCTION_LIST* g_FunctionPtr = NULL;

int RT_P11_API_SetMetas(
	unsigned char *pAuthKey, int uiAuthKeyLen,
	unsigned char *pSecID, int uiSecIDLen,
	unsigned char *pHMac, int uiHMacLen,
	char * pszPIN, unsigned int * pulRetry
	)
{


	{{
		// this add secid
	}}


	{{
		// HMAC密钥
		// 每个用户有9个HMAC密钥，每个密钥长度为32字节
		// 09 +
		// 0120 3131313131313131313131313131313131313131313131313131313131313131 +
		// 0220 3232323232323232323232323232323232323232323232323232323232323232 +
		// 0320 3333333333333333333333333333333333333333333333333333333333333333 +
		// 0420 3434343434343434343434343434343434343434343434343434343434343434 +
		// 0520 3535353535353535353535353535353535353535353535353535353535353535 +
		// 0620 3636363636363636363636363636363636363636363636363636363636363636 +
		// 0720 3737373737373737373737373737373737373737373737373737373737373737 + 
		// 0820 3838383838383838383838383838383838383838383838383838383838383838 + 09 3939393939393939393939393939393939393939393939393939393939393939

		// A类用户
		// char *pszHMACKey = "03012031313131313131313131313131313131313131313131313131313131313131310520353535353535353535353535353535353535353535353535353535353535353506203636363636363636363636363636363636363636363636363636363636363636";
		unsigned char bHMACKey[512];

		CK_KEY_TYPE		keyType = CKK_GENERIC_SECRET;
		CK_OBJECT_CLASS SecretClass = CKO_SECRET_KEY;
		CK_ATTRIBUTE KPXTemplate[] = {
			{CKA_CLASS, &SecretClass, sizeof(SecretClass)},
			{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
			{CKA_TOKEN, &True, sizeof(True)},
			{CKA_ID, RT_HMAC_KEY, strlen(RT_HMAC_KEY)},
			{CKA_ENCRYPT, &True, sizeof(True)},
			{CKA_VALUE, (unsigned char *)bHMACKey, 1+1+32+1+32+32}
		};
		CK_OBJECT_HANDLE hKPX=NULL_PTR;
		int pos = 0;

		switch(pSecID[0])
		{
		case 1:
			//A类用户CKA_VALUE：
			//	03 + {01+20+HK1} + {05+20+HK5} + {06+20+HK6}
			pos = 0;
			bHMACKey[pos] = 0x03;
			pos+=1;
			bHMACKey[pos] = 0x01;
			pos+=1;
			bHMACKey[pos] = 0x20;
			pos+=1;
			memcpy(bHMACKey+pos,pHMac+(0x01-1)*32,32);
			pos+=32;
			bHMACKey[pos] = 0x05;
			pos+=1;
			bHMACKey[pos] = 0x20;
			pos+=1;
			memcpy(bHMACKey+pos,pHMac+(0x05-1)*32,32);
			pos+=32;
			bHMACKey[pos] = 0x06;
			pos+=1;
			bHMACKey[pos] = 0x20;
			pos+=1;
			memcpy(bHMACKey+pos,pHMac+(0x06-1)*32,32);
			pos+=32;
			KPXTemplate[5].ulValueLen = pos;
			break;
		case 2:
			//B0类用户CKA_VALUE：
			//	04 + {02+20+HK2} + {06+20+HK6} + {07+20+HK7} + {08+20+HK8}
			pos = 0;
			bHMACKey[pos] = 0x04;
			pos+=1;
			bHMACKey[pos] = 0x02;
			pos+=1;
			bHMACKey[pos] = 0x20;
			pos+=1;
			memcpy(bHMACKey+pos,pHMac+(0x02-1)*32,32);
			pos+=32;
			bHMACKey[pos] = 0x06;
			pos+=1;
			bHMACKey[pos] = 0x20;
			pos+=1;
			memcpy(bHMACKey+pos,pHMac+(0x06-1)*32,32);
			pos+=32;
			bHMACKey[pos] = 0x07;
			pos+=1;
			bHMACKey[pos] = 0x20;
			pos+=1;
			memcpy(bHMACKey+pos,pHMac+(0x07-1)*32,32);
			pos+=32;
			bHMACKey[pos] = 0x08;
			pos+=1;
			bHMACKey[pos] = 0x20;
			pos+=1;
			memcpy(bHMACKey+pos,pHMac+(0x08-1)*32,32);
			pos+=32;
			KPXTemplate[5].ulValueLen = pos;
			break;
		case 3:
			//B1类用户CKA_VALUE：
			//	02 + {03+20+HK3} + {08+20+HK8}
			pos = 0;
			bHMACKey[pos] = 0x02;
			pos+=1;
			bHMACKey[pos] = 0x03;
			pos+=1;
			bHMACKey[pos] = 0x20;
			pos+=1;
			memcpy(bHMACKey+pos,pHMac+(0x03-1)*32,32);
			pos+=32;
			bHMACKey[pos] = 0x08;
			pos+=1;
			bHMACKey[pos] = 0x20;
			pos+=1;
			memcpy(bHMACKey+pos,pHMac+(0x08-1)*32,32);
			pos+=32;
			KPXTemplate[5].ulValueLen = pos;
			break;
		case 4:
			//C类用户CKA_VALUE：
			//	03 + {04+20+HK4} + {08+20+HK8} + {09+20+HK9}
			pos = 0;
			bHMACKey[pos] = 0x03;
			pos+=1;
			bHMACKey[pos] = 0x04;
			pos+=1;
			bHMACKey[pos] = 0x20;
			pos+=1;
			memcpy(bHMACKey+pos,pHMac+(0x04-1)*32,32);
			pos+=32;
			bHMACKey[pos] = 0x08;
			pos+=1;
			bHMACKey[pos] = 0x20;
			pos+=1;
			memcpy(bHMACKey+pos,pHMac+(0x08-1)*32,32);
			pos+=32;
			bHMACKey[pos] = 0x09;
			pos+=1;
			bHMACKey[pos] = 0x20;
			pos+=1;
			memcpy(bHMACKey+pos,pHMac+(0x09-1)*32,32);
			pos+=32;
			KPXTemplate[5].ulValueLen = pos;
			break;
		default:
			break;
		}

		IN_StrToHex(pszHMACKey, strlen(pszHMACKey), bHMACKey);
		KPXTemplate[5].ulValueLen = strlen(pszHMACKey)/2;

		rv = g_FunctionPtr->C_CreateObject(hSession, KPXTemplate, sizeof(KPXTemplate) / sizeof(CK_ATTRIBUTE), &hKPX);
		if (rv != CKR_OK) {
			wsprintf(szMsg,TEXT("C_CreateObject<HMAC> error, error code: 0x%08x."),rv);
			m_MsgList.AddString(szMsg);
			UpdateWindow();
			goto EndOP;
		}
		wsprintf(szMsg,TEXT("C_CreateObject<HMAC> ok."));
		m_MsgList.AddString(szMsg);
		UpdateWindow();
	}}
}

int RT_P11_API_SetZMMetas(
	unsigned char *pAuthKey, int uiAuthKeyLen,
	unsigned char *pZMP, int uiZMPLen,
	unsigned char *pSignKey, int uiSignKeyLen,
	unsigned char *pCryptKey, int uiCryptKeyLen,
	unsigned char *pExchangeKey, int uiExchangeKeyLen,
	char * pszPIN, unsigned int * pulRetry
	)
{
	{{ // 创建文件
		// r1加密后的A类用户（KPA）：  0x02 + 0x31 + BE087F4168213C144B6DA3AACBF5D056BE087F4168213C144B6DA3AACBF5D056 + 0x32 + FAAAAE0892E71A69BAC81ECC3CCD3E1BFAAAAE0892E71A69BAC81ECC3CCD3E1B
		// r3: 0303030303030303030303030303030303030303030303030303030303030303
		// data: KPA||r3
		//unsigned char *pbKPX = (unsigned char*)"\x02\x31\xBE\x08\x7F\x41\x68\x21\x3C\x14\x4B\x6D\xA3\xAA\xCB\xF5\xD0\x56\xBE\x08\x7F\x41\x68\x21\x3C\x14\x4B\x6D\xA3\xAA\xCB\xF5\xD0\x56\x32\xFA\xAA\xAE\x08\x92\xE7\x1A\x69\xBA\xC8\x1E\xCC\x3C\xCD\x3E\x1B\xFA\xAA\xAE\x08\x92\xE7\x1A\x69\xBA\xC8\x1E\xCC\x3C\xCD\x3E\x1B\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03";
		unsigned char *pbKPX = (unsigned char*)"\x02\x31\xBE\x08\x7F\x41\x68\x21\x3C\x14\x4B\x6D\xA3\xAA\xCB\xF5\xD0\x56\xBE\x08\x7F\x41\x68\x21\x3C\x14\x4B\x6D\xA3\xAA\xCB\xF5\xD0\x56\x32\xFA\xAA\xAE\x08\x92\xE7\x1A\x69\xBA\xC8\x1E\xCC\x3C\xCD\x3E\x1B\xFA\xAA\xAE\x08\x92\xE7\x1A\x69\xBA\xC8\x1E\xCC\x3C\xCD\x3E\x1B\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03";
		//unsigned char *pbKPX = (unsigned char*)"\x02\x31\xBE\x08\x7F\x41\x68\x21\x3C\x14\x4B\x6D\xA3\xAA\xCB\xF5\xD0\x56\xBE\x08\x7F\x41\x68\x21\x3C\x14\x4B\x6D\xA3\xAA\xCB\xF5\xD0\x56\x32\xFA\xAA\xAE\x08\x92\xE7\x1A\x69\xBA\xC8\x1E\xCC\x3C\xCD\x3E\x1B\xFA\xAA\xAE\x08\x92\xE7\x1A\x69\xBA\xC8\x1E\xCC\x3C\xCD\x3E\x1B\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

		CK_KEY_TYPE		keyType = CKK_GENERIC_SECRET;
		CK_OBJECT_CLASS SecretClass = CKO_SECRET_KEY;
		CK_ATTRIBUTE KPXTemplate[] = {
			{CKA_CLASS, &SecretClass, sizeof(SecretClass)},
			{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
			{CKA_TOKEN, &True, sizeof(True)},
			{CKA_ID, pszKPX_CKAID, strlen(pszKPX_CKAID)},
			{CKA_ENCRYPT, &True, sizeof(True)},
			{CKA_VALUE, (unsigned char *)pbKPX, 1+1+32+1+32+32}
		};
		CK_OBJECT_HANDLE hKPX=NULL_PTR;

		rv = g_FunctionPtr->C_CreateObject(hSession, KPXTemplate, sizeof(KPXTemplate) / sizeof(CK_ATTRIBUTE), &hKPX);
		if (rv != CKR_OK) {
			wsprintf(szMsg,TEXT("C_CreateObject<KPX> error, error code: 0x%08x."),rv);
			m_MsgList.AddString(szMsg);
			UpdateWindow();
			goto EndOP;
		}
		wsprintf(szMsg,TEXT("C_CreateObject<KPX> ok."));
		m_MsgList.AddString(szMsg);
		UpdateWindow();
	}}


	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// 专密
	{{ // ECC512签名密钥对

		CK_OBJECT_CLASS PubClass = CKO_PUBLIC_KEY;
		CK_OBJECT_CLASS PrivateClass = CKO_PRIVATE_KEY;

		CK_KEY_TYPE KeyType = CKK_ECC512;
		CK_ULONG ulBits = 512;

		unsigned char bPubX[64], bPubY[64], bPri[64];

		char *pszPub = "3C38323473E06F922A7B1309FA8DD61FEE05ED6E0B85D7C9B7C13218E4DC28F519E3DB21B24BBFB393927583A6416E0C4DA3A64080B81B8A7C36A80A9D7DA6BA3DAD4DA77DCC7573FB3B400914184D5FFAD0225077AED46BCBC2C4E0F10A96B62702AEC66570A1DB6EAA9933DDD1B4B1C87BA90C6AA635058695EC15A767DEF1";
		// 密文私钥
		char *pszPri = "9EBDB1CD25754F5A5DA1508BCF0A882D950BA10E5D5BC8B036AC11743946487A5DBF841D70472592AE07D8415B6F4185CA68BE6639CF2E5C80A02A6E54CCC61D";

		CK_ULONG ulPubKeyCount, ulPriKeyCount;

		CK_OBJECT_HANDLE hPubKey = NULL;
		CK_OBJECT_HANDLE hPriKey = NULL;

		CK_ATTRIBUTE ECC512CreatePublicKeyTemplate[] = {
			{CKA_CLASS, &PubClass, sizeof(PubClass)},
			{CKA_KEY_TYPE, &KeyType, sizeof(KeyType)},
			{CKA_ID,    pszECC512Sign_CKAID, strlen(pszECC512Sign_CKAID)}, 
			{CKA_TOKEN, &True, sizeof(True)},
			{CKA_PRIVATE, &bFalse, sizeof(bFalse)},
			{CKA_ENCRYPT, &True, sizeof(True)},
			{CKA_VERIFY, &True, sizeof(True)},
			{CKA_ECC512_PUBLIC_X, bPubX, 64},
			{CKA_ECC512_PUBLIC_Y, bPubY, 64},
			{CKA_ECC512_BITS, &ulBits, sizeof (ulBits)}
		};

		CK_ATTRIBUTE ECC512CreatePrivateKeyTemplate[] = {
			{CKA_CLASS, &PrivateClass, sizeof(PrivateClass)},
			{CKA_KEY_TYPE, &KeyType, sizeof(KeyType)},
			{CKA_ID,    pszECC512Sign_CKAID, strlen(pszECC512Sign_CKAID)}, 
			{CKA_TOKEN, &True, sizeof(True)},
			{CKA_PRIVATE, &True, sizeof(True)},
			{CKA_DECRYPT, &True, sizeof(True)},
			{CKA_SIGN, &True, sizeof(True)},
			{CKA_ECC512_PUBLIC_X, bPubX, 64},
			{CKA_ECC512_PUBLIC_Y, bPubY, 64},
			{CKA_ECC512_BITS, &ulBits, sizeof (ulBits)},
			{CKA_ECC512_PRIVATE_KEY, bPri, 64}
		};
		ulPubKeyCount = sizeof(ECC512CreatePublicKeyTemplate) / sizeof(CK_ATTRIBUTE);
		ulPriKeyCount = sizeof(ECC512CreatePrivateKeyTemplate) / sizeof(CK_ATTRIBUTE);

		IN_StrToHex(pszPub, 128, bPubX);
		IN_StrToHex(pszPub+128, 128, bPubY);
		IN_StrToHex(pszPri, 128, bPri);

		rv = g_FunctionPtr->C_CreateObject(hSession, ECC512CreatePublicKeyTemplate, ulPubKeyCount, &hPubKey);
		if (rv != CKR_OK) {
			wsprintf(szMsg,TEXT("C_CreateObject<ECC512 SignPubKey> error, error code: 0x%08x."),rv);
			m_MsgList.AddString(szMsg);
			UpdateWindow();
			goto EndOP;
		}
		wsprintf(szMsg,TEXT("C_CreateObject<ECC512 SignPubKey> ok."));
		m_MsgList.AddString(szMsg);
		UpdateWindow();

		rv = g_FunctionPtr->C_CreateObject(hSession, ECC512CreatePrivateKeyTemplate, ulPriKeyCount, &hPriKey);
		if (rv != CKR_OK) {
			wsprintf(szMsg,TEXT("C_CreateObject<ECC512 SignPriKey> error, error code: 0x%08x."),rv);
			m_MsgList.AddString(szMsg);
			UpdateWindow();
			goto EndOP;
		}
		wsprintf(szMsg,TEXT("C_CreateObject<ECC512 SignPriKey> ok."));
		m_MsgList.AddString(szMsg);
		UpdateWindow();
	}}



	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// 专密
	{{ // ECC512加密密钥对

		CK_OBJECT_CLASS PubClass = CKO_PUBLIC_KEY;
		CK_OBJECT_CLASS PrivateClass = CKO_PRIVATE_KEY;

		CK_KEY_TYPE KeyType = CKK_ECC512;
		CK_ULONG ulBits = 512;

		unsigned char bPubX[64], bPubY[64], bPri[64];

		char *pszPub = "B94126B7ED5A2DED7B6D91712E330310C2546ACB19A028389725C8D8314DFC8FC7791F9BC156317090376B06D3C7F60C0B91BBB50B929C4DF344CAACAD55D1ED20C28DCD586F97C3E2276FDB9A9190292FC36DB2264F030D3E40C0022952C554756A96831C7F6604D505E3448FFE50E9C505ACFD5AA54115A9A41DEE4D572B90";
		// 密文私钥
		char *pszPri = "70E20553368A5C0D3C4C38DF635D04F49B37E087970E90B2AE06013CDFFE968FCD30A0EFB86BC1CEFB6B240FB66AE3743BF5F64FE02DCDE80FA4489A965116BD";

		CK_ULONG ulPubKeyCount, ulPriKeyCount;

		CK_OBJECT_HANDLE hPubKey = NULL;
		CK_OBJECT_HANDLE hPriKey = NULL;

		CK_ATTRIBUTE ECC512CreatePublicKeyTemplate[] = {
			{CKA_CLASS, &PubClass, sizeof(PubClass)},
			{CKA_KEY_TYPE, &KeyType, sizeof(KeyType)},
			{CKA_ID,    pszECC512Enc_CKAID, strlen(pszECC512Enc_CKAID)}, 
			{CKA_TOKEN, &True, sizeof(True)},
			{CKA_PRIVATE, &bFalse, sizeof(bFalse)},
			{CKA_ENCRYPT, &True, sizeof(True)},
			{CKA_VERIFY, &True, sizeof(True)},
			{CKA_ECC512_PUBLIC_X, bPubX, 64},
			{CKA_ECC512_PUBLIC_Y, bPubY, 64},
			{CKA_ECC512_BITS, &ulBits, sizeof (ulBits)}
		};

		CK_ATTRIBUTE ECC512CreatePrivateKeyTemplate[] = {
			{CKA_CLASS, &PrivateClass, sizeof(PrivateClass)},
			{CKA_KEY_TYPE, &KeyType, sizeof(KeyType)},
			{CKA_ID,    pszECC512Enc_CKAID, strlen(pszECC512Enc_CKAID)}, 
			{CKA_TOKEN, &True, sizeof(True)},
			{CKA_PRIVATE, &True, sizeof(True)},
			{CKA_DECRYPT, &True, sizeof(True)},
			{CKA_SIGN, &True, sizeof(True)},
			{CKA_ECC512_PUBLIC_X, bPubX, 64},
			{CKA_ECC512_PUBLIC_Y, bPubY, 64},
			{CKA_ECC512_BITS, &ulBits, sizeof (ulBits)},
			{CKA_ECC512_PRIVATE_KEY, bPri, 64}
		};
		ulPubKeyCount = sizeof(ECC512CreatePublicKeyTemplate) / sizeof(CK_ATTRIBUTE);
		ulPriKeyCount = sizeof(ECC512CreatePrivateKeyTemplate) / sizeof(CK_ATTRIBUTE);

		IN_StrToHex(pszPub, 128, bPubX);
		IN_StrToHex(pszPub+128, 128, bPubY);
		IN_StrToHex(pszPri, 128, bPri);

		rv = g_FunctionPtr->C_CreateObject(hSession, ECC512CreatePublicKeyTemplate, ulPubKeyCount, &hPubKey);
		if (rv != CKR_OK) {
			wsprintf(szMsg,TEXT("C_CreateObject<ECC512 EncPubKey> error, error code: 0x%08x."),rv);
			m_MsgList.AddString(szMsg);
			UpdateWindow();
			goto EndOP;
		}
		wsprintf(szMsg,TEXT("C_CreateObject<ECC512 EncPubKey> ok."));
		m_MsgList.AddString(szMsg);
		UpdateWindow();

		rv = g_FunctionPtr->C_CreateObject(hSession, ECC512CreatePrivateKeyTemplate, ulPriKeyCount, &hPriKey);
		if (rv != CKR_OK) {
			wsprintf(szMsg,TEXT("C_CreateObject<ECC512 EncPriKey> error, error code: 0x%08x."),rv);
			m_MsgList.AddString(szMsg);
			UpdateWindow();
			goto EndOP;
		}
		wsprintf(szMsg,TEXT("C_CreateObject<ECC512 EncPriKey> ok."));
		m_MsgList.AddString(szMsg);
		UpdateWindow();
	}}



	///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	// 专密
	{{ // ECC512交换钥对

		CK_OBJECT_CLASS PubClass = CKO_PUBLIC_KEY;
		CK_OBJECT_CLASS PrivateClass = CKO_PRIVATE_KEY;

		CK_KEY_TYPE KeyType = CKK_ECC512;
		CK_ULONG ulBits = 512;

		unsigned char bPubX[64], bPubY[64], bPri[64];

		char *pszPub = "95A2768BD82CF689540E3D1C3D6E2F7C06DC693706B731363C18927DBC08EE5828DD4422AC7559197536F5E99B1277A56FAC7EFA47EBBCAA57CBD44AD793E61243AC095ECD2BD5247875551B9E46B614FC6E909C905521B22E9CEE407DB118C4BFAE7AA4D035CAAADDE0DB11E4C32A343282F71C35F922442927641146BACF3E";
		// 密文私钥
		char *pszPri = "56542FCA38140CCCA8DEFB8DF90E6394BBE45EBD8107B822C54D1FB61D7202D6D22B3529A2483190F4460368321B38CFAC2344C8A997D71A962D966D3A1B4BC3";

		CK_ULONG ulPubKeyCount, ulPriKeyCount;

		CK_OBJECT_HANDLE hPubKey = NULL;
		CK_OBJECT_HANDLE hPriKey = NULL;

		CK_ATTRIBUTE ECC512CreatePublicKeyTemplate[] = {
			{CKA_CLASS, &PubClass, sizeof(PubClass)},
			{CKA_KEY_TYPE, &KeyType, sizeof(KeyType)},
			{CKA_ID,    pszECC512Exc_CKAID, strlen(pszECC512Exc_CKAID)}, 
			{CKA_TOKEN, &True, sizeof(True)},
			{CKA_PRIVATE, &bFalse, sizeof(bFalse)},
			{CKA_ENCRYPT, &True, sizeof(True)},
			{CKA_VERIFY, &True, sizeof(True)},
			{CKA_ECC512_PUBLIC_X, bPubX, 64},
			{CKA_ECC512_PUBLIC_Y, bPubY, 64},
			{CKA_ECC512_BITS, &ulBits, sizeof (ulBits)}
		};

		CK_ATTRIBUTE ECC512CreatePrivateKeyTemplate[] = {
			{CKA_CLASS, &PrivateClass, sizeof(PrivateClass)},
			{CKA_KEY_TYPE, &KeyType, sizeof(KeyType)},
			{CKA_ID,    pszECC512Exc_CKAID, strlen(pszECC512Exc_CKAID)}, 
			{CKA_TOKEN, &True, sizeof(True)},
			{CKA_PRIVATE, &True, sizeof(True)},
			{CKA_DECRYPT, &True, sizeof(True)},
			{CKA_SIGN, &True, sizeof(True)},
			{CKA_ECC512_PUBLIC_X, bPubX, 64},
			{CKA_ECC512_PUBLIC_Y, bPubY, 64},
			{CKA_ECC512_BITS, &ulBits, sizeof (ulBits)},
			{CKA_ECC512_PRIVATE_KEY, bPri, 64}
		};
		ulPubKeyCount = sizeof(ECC512CreatePublicKeyTemplate) / sizeof(CK_ATTRIBUTE);
		ulPriKeyCount = sizeof(ECC512CreatePrivateKeyTemplate) / sizeof(CK_ATTRIBUTE);

		IN_StrToHex(pszPub, 128, bPubX);
		IN_StrToHex(pszPub+128, 128, bPubY);
		IN_StrToHex(pszPri, 128, bPri);

		rv = g_FunctionPtr->C_CreateObject(hSession, ECC512CreatePublicKeyTemplate, ulPubKeyCount, &hPubKey);
		if (rv != CKR_OK) {
			wsprintf(szMsg,TEXT("C_CreateObject<ECC512 ExcPubKey> error, error code: 0x%08x."),rv);
			m_MsgList.AddString(szMsg);
			UpdateWindow();
			goto EndOP;
		}
		wsprintf(szMsg,TEXT("C_CreateObject<ECC512 ExcPubKey> ok."));
		m_MsgList.AddString(szMsg);
		UpdateWindow();

		rv = g_FunctionPtr->C_CreateObject(hSession, ECC512CreatePrivateKeyTemplate, ulPriKeyCount, &hPriKey);
		if (rv != CKR_OK) {
			wsprintf(szMsg,TEXT("C_CreateObject<ECC512 ExcPriKey> error, error code: 0x%08x."),rv);
			m_MsgList.AddString(szMsg);
			UpdateWindow();
			goto EndOP;
		}
		wsprintf(szMsg,TEXT("C_CreateObject<ECC512 ExcPriKey> ok."));
		m_MsgList.AddString(szMsg);
		UpdateWindow();
	}}
}

int RT_P11_API_SetZMCerts(
	unsigned char *pAuthKey, int uiAuthKeyLen,
	unsigned char *pSignCert, int uiSignCertLen,
	unsigned char *pCryptCert, int uiCryptCertLen,
	unsigned char *pExchangeCert, int uiExchangeCertLen,
	char * pszPIN, unsigned int * pulRetry
	)
{

}

int RT_P11_API_GetCertCount(
	unsigned char *pAuthKey, int uiAuthKeyLen,
	unsigned int *CertCount,
	char * pszPIN, unsigned int * pulRetry
	)
{

}
