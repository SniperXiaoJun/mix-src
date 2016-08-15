#include "pci_func_def.h"
#include "stdlib.h"
#include "string.h"
#include "o_all_type_def.h"
#include "FILE_LOG.h"

//#include "SKFInterface.h"


#define PCI_MAIN_KEY_ECC 1
#define PCI_MAIN_KEY_ECC_EX		(PCI_MAIN_KEY_ECC << 1)
#define PCI_MAIN_KEY_ECC_SIGN	(PCI_MAIN_KEY_ECC << 1 - 1)
#define PCI_MAIN_KEY_SYM 1
#define PCI_ECC_MAX_KEY 100


// 定制接口
SGD_RV SWCSM_GenerateECCKeyPair(SGD_HANDLE , SGD_UINT32);
SGD_RV SWCSM_DestoryECCKeyPair(SGD_HANDLE , SGD_UINT32);
SGD_RV SDF_GetKeyStatus(SGD_HANDLE hSessionHandle, SGD_UINT32 uiKeyType, SGD_UINT32 *puiKeyStatus, SGD_UINT32 *puiKeyCount);
SGD_RV SWCSM_Login(SGD_HANDLE, SGD_UCHAR *, SGD_UINT32 *);
SGD_RV SWCSM_Logout(SGD_HANDLE, SGD_UINT32);

SGD_RV SWCSM_BackupInit(SGD_HANDLE, SGD_UINT32);
SGD_RV SWCSM_BackupExportKeyComponent(SGD_HANDLE, SGD_UINT32, SGD_UINT8 *);
SGD_RV SWCSM_BackupExportKEK(SGD_HANDLE,SGD_UINT32,SGD_UINT8 *, SGD_UINT32 *);
SGD_RV SWCSM_BackupExportECCKey(SGD_HANDLE hSessionHandle,SGD_UINT32 uiIndex, SGD_UINT32 * puiKeyBits, SGD_UCHAR *pucKeyData,SGD_UINT32 * puiKeyDataLength);

SGD_RV SWCSM_BackupFinal(SGD_HANDLE);

SGD_RV SWCSM_RestoreInit(SGD_HANDLE, SGD_UINT32);
SGD_RV SWCSM_RestoreImportKeyComponent(SGD_HANDLE, SGD_UINT8 *);
SGD_RV SWCSM_RestoreImportKEK(SGD_HANDLE, SGD_UINT32,SGD_UINT8 *, SGD_UINT32);
SGD_RV SWCSM_RestoreImportECCKey(SGD_HANDLE hSessionHandle,SGD_UINT32 uiIndex, SGD_UINT32 uiKeyBits, SGD_UCHAR *pucKeyData,SGD_UINT32 uiKeyDataLength);
SGD_RV SWCSM_RestoreFinal(SGD_HANDLE);

int SWCSM_ImportECCKeyPair(
	SGD_HANDLE hSessionHandle, 
	unsigned int  uiKeyNumber,
	ECCrefPublicKey *pucPublicKey,
	ECCrefPrivateKey *pucPrivateKey);


unsigned int	PCI_Open(HANDLE *phPCIHandle, HANDLE *phSessionHandle)
{
	unsigned int	uiRes = 0;

	SGD_HANDLE hDeviceHandle = NULL;
	SGD_HANDLE hSessionHandle = NULL;

#ifndef	PCI_TEST	

	if ( NULL == phPCIHandle || NULL == phSessionHandle)
	{
		return PCI_PARAM_ERR;
	}

	uiRes = SDF_OpenDevice(&hDeviceHandle);
	if(uiRes != SDR_OK)
	{
		return uiRes;
	}

	uiRes = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if(uiRes != SDR_OK)
	{
		SDF_CloseDevice(hDeviceHandle);
	}
	else
	{
		*phPCIHandle = hDeviceHandle;
		*phSessionHandle = hSessionHandle;
	}

#else

#endif 

	return uiRes;
}


unsigned int	PCI_Close(HANDLE hPCIHandle, HANDLE hSessionHandle)
{
	unsigned int	uiRes = 0;


#ifndef	PCI_TEST

	if(hSessionHandle != NULL)
	{
		uiRes = SDF_CloseSession(hSessionHandle);
	}

	if(hPCIHandle != NULL)
	{
		uiRes = SDF_CloseDevice(hPCIHandle);
	}

#else

#endif 

	return uiRes;
}


unsigned int PCI_ICLogin(HANDLE hSessionHandle,
	const unsigned char* pbPINValue, unsigned int uiPINLen , 
	unsigned int *puiUserID, unsigned int *puiTrials)
{
	unsigned int	uiRes = 0;

	if ( NULL == pbPINValue || 8 != uiPINLen || NULL == puiUserID || NULL == puiTrials )
	{
		return PCI_PARAM_ERR;
	}

	uiRes = SWCSM_Login(hSessionHandle,(SGD_UCHAR *)pbPINValue,(SGD_UINT32 *)puiUserID);
	if ( 0x01036200 == uiRes )
	{
		uiRes = PCI_CARD_NO_FIND_IC;
	}
	else if ( ((SWR_CARD_READER_PIN_ERROR) >> 8) == (uiRes >> 8) )	// IC卡口令错误
	{
		*puiTrials = uiRes & 0x0F;
		uiRes = PCI_CARD_IC_PIN_ERR;
	}
	else if ( 0x01036983 == uiRes )	// IC卡已锁死
	{
		uiRes = PCI_CARD_IC_PIN_LOCK_ERR;
	}
	else if( 0x01036400 == uiRes )
	{
		uiRes = PCI_CARD_INSERT_ERR;
	}

	return uiRes;
}


unsigned int PCI_ICLogout(HANDLE hSessionHandle, unsigned int uiUserID)
{
	unsigned int	uiRes = 0;

#ifndef	PCI_TEST
	uiRes = SWCSM_Logout(hSessionHandle, uiUserID);
#else

#endif

	return uiRes;
}


unsigned int PCI_GenExportSM2EnvelopedKey(HANDLE hSessionHandle, unsigned char *pbPubkeyX,unsigned char *pbPubkeyY,
	void * pvENVELOPEDKEYBLOB_IPK, void * pvENVELOPEDKEYBLOB_EPK)
{
	unsigned int	uiRes = 0;

	ECCCipher stECCCipherIPK = {0};					// 内部公钥加密密文
	ECCCipher stECCCipherEPK = {0};					// 外部公钥加密密文

	HANDLE hKEY = 0;								// 密钥加密密钥句柄
	ECCrefPublicKey  stECC_EPK =    {0};			// ECC外部加密公钥
	ECCrefPublicKey  stECC_PK_Gen = {0};			// ECC生成钥（待生成）
	ECCrefPrivateKey stECC_SK_Gen = {0};			// ECC生成密钥（待生成）
	unsigned int uiSymAlg = SGD_SM1_ECB;			// 密钥加密密钥对称算法
	unsigned int uiEnPrivakeyLen = ECCref_MAX_LEN;	// 密文私钥长度
	unsigned char cbEnPrivakey[ECCref_MAX_LEN] = {0};// 密文私钥
	unsigned int uiSKBitLen = 128;	// 加密私钥长度
	OPST_SKF_ENVELOPEDKEYBLOB * pENVELOPEDKEYBLOB_IPK = NULL;	// 内部公钥加密数字信封
	OPST_SKF_ENVELOPEDKEYBLOB * pENVELOPEDKEYBLOB_EPK = NULL;	// 外部公钥加密数字信封

	pENVELOPEDKEYBLOB_IPK = (OPST_SKF_ENVELOPEDKEYBLOB *)pvENVELOPEDKEYBLOB_IPK;
	pENVELOPEDKEYBLOB_EPK = (OPST_SKF_ENVELOPEDKEYBLOB *)pvENVELOPEDKEYBLOB_EPK;

	if (pENVELOPEDKEYBLOB_IPK && pENVELOPEDKEYBLOB_EPK)
	{
		memset(pENVELOPEDKEYBLOB_IPK,0, sizeof(OPST_SKF_ENVELOPEDKEYBLOB));
		memset(pENVELOPEDKEYBLOB_EPK,0, sizeof(OPST_SKF_ENVELOPEDKEYBLOB));
	}
	else
	{
		uiRes = PCI_PARAM_ERR;
		goto err;
	}

	// 初始化外部公钥
	stECC_EPK.bits = ECCref_MAX_BITS;
	memcpy(stECC_EPK.x, pbPubkeyX, ECCref_MAX_LEN);
	memcpy(stECC_EPK.y, pbPubkeyY, ECCref_MAX_LEN);

	// 生成ECC密钥对
	uiRes = SDF_GenerateKeyPair_ECC(
		hSessionHandle, 
		KEY_TYPE_ECC,
		ECCref_MAX_BITS,
		&stECC_PK_Gen,
		&stECC_SK_Gen);

	if (0 == uiRes)
	{

	}
	else
	{
		goto err;
	}

	// 生成密钥加密密钥（外部）
	//uiRes = SDF_GenerateKeyWithEPK_ECC (
	//	hSessionHandle, 
	//	uiSKBitLen,
	//	uiSymAlg,
	//	&stECC_EPK,
	//	&stECCCipherEPK,
	//	&hKEY);

	// 生成密钥加密密钥(内部)
	uiRes = SDF_GenerateKeyWithIPK_ECC (
		hSessionHandle, 
		PCI_MAIN_KEY_ECC,
		uiSKBitLen,
		&stECCCipherIPK,
		&hKEY);

	if (0 == uiRes)
	{

	}
	else
	{
		goto err;
	}

	// 数字信封转换（内部转外部）
	uiRes = SDF_ExchangeDigitEnvelopeBaseOnECC(hSessionHandle,PCI_MAIN_KEY_ECC,KEY_TYPE_ECC,&stECC_EPK,&stECCCipherIPK,&stECCCipherEPK);

	if(0 == uiRes)
	{

	}
	else
	{
		goto err;
	}

	// 对私钥进行加密
	uiRes = SDF_Encrypt(hSessionHandle,hKEY,uiSymAlg,NULL,
		stECC_SK_Gen.D,ECCref_MAX_LEN,
		cbEnPrivakey,&uiEnPrivakeyLen);

	if (0 == uiRes)
	{

	}
	else
	{
		goto err;
	}

	// 设置输出数据
	{
		// 版本
		pENVELOPEDKEYBLOB_IPK->Version = 1;

		// 密文私钥
		memcpy(pENVELOPEDKEYBLOB_IPK->cbEncryptedPriKey+ECCref_MAX_LEN,cbEnPrivakey,ECCref_MAX_LEN);

		// 位长度
		pENVELOPEDKEYBLOB_IPK->uiBits = ECC_MAX_XCOORDINATE_BITS_LEN / 2;

		// 算法
		pENVELOPEDKEYBLOB_IPK->uiSymmAlgID = uiSymAlg;

		// 公钥赋值
		pENVELOPEDKEYBLOB_IPK->PubKey.BitLen = ECCref_MAX_BITS;
		memcpy(pENVELOPEDKEYBLOB_IPK->PubKey.XCoordinate + ECCref_MAX_LEN,stECC_PK_Gen.x,ECCref_MAX_LEN);
		memcpy(pENVELOPEDKEYBLOB_IPK->PubKey.YCoordinate + ECCref_MAX_LEN,stECC_PK_Gen.y,ECCref_MAX_LEN);

		// 设置
		memcpy(pENVELOPEDKEYBLOB_EPK, pENVELOPEDKEYBLOB_IPK , sizeof(OPST_SKF_ENVELOPEDKEYBLOB));

		// 数字信封（密文私钥）
		pENVELOPEDKEYBLOB_IPK->ECCCipherBlob.CipherLen = stECCCipherIPK.clength;
		memcpy(pENVELOPEDKEYBLOB_IPK->ECCCipherBlob.HASH,stECCCipherIPK.M,ECCref_MAX_LEN);
		memcpy(pENVELOPEDKEYBLOB_IPK->ECCCipherBlob.XCoordinate + ECCref_MAX_LEN,stECCCipherIPK.x,ECCref_MAX_LEN);
		memcpy(pENVELOPEDKEYBLOB_IPK->ECCCipherBlob.YCoordinate + ECCref_MAX_LEN,stECCCipherIPK.y,ECCref_MAX_LEN);
		memcpy(pENVELOPEDKEYBLOB_IPK->ECCCipherBlob.Cipher,stECCCipherIPK.C,stECCCipherIPK.clength);

		// 数字信封（密文私钥）
		pENVELOPEDKEYBLOB_EPK->ECCCipherBlob.CipherLen = stECCCipherEPK.clength;
		memcpy(pENVELOPEDKEYBLOB_EPK->ECCCipherBlob.HASH,stECCCipherEPK.M,ECCref_MAX_LEN);
		memcpy(pENVELOPEDKEYBLOB_EPK->ECCCipherBlob.XCoordinate + ECCref_MAX_LEN,stECCCipherEPK.x,ECCref_MAX_LEN);
		memcpy(pENVELOPEDKEYBLOB_EPK->ECCCipherBlob.YCoordinate + ECCref_MAX_LEN,stECCCipherEPK.y,ECCref_MAX_LEN);
		memcpy(pENVELOPEDKEYBLOB_EPK->ECCCipherBlob.Cipher,stECCCipherEPK.C,stECCCipherEPK.clength);
	}
err:

	return uiRes;
}


unsigned int PCI_RestoreExportSM2EnvelopedKey(HANDLE hSessionHandle, unsigned char *pbPubkeyX,unsigned char *pbPubkeyY, 
	void * pvENVELOPEDKEYBLOB_IPK, void * pvENVELOPEDKEYBLOB_EPK)
{
	unsigned int	uiRes = 0;

	ECCCipher stECCCipherIPK = {0};					// 内部公钥加密密文
	ECCCipher stECCCipherEPK = {0};					// 外部公钥加密密文

	HANDLE hKEY = 0;								// 密钥加密密钥句柄
	ECCrefPublicKey  stECC_EPK =    {0};			// ECC外部加密公钥
	unsigned int uiSymAlg = SGD_SM1_ECB;			// 密钥加密密钥对称算法
	unsigned int uiSKBitLen = 128;	// 加密私钥长度
	OPST_SKF_ENVELOPEDKEYBLOB * pENVELOPEDKEYBLOB_IPK = NULL;	// 内部公钥加密数字信封
	OPST_SKF_ENVELOPEDKEYBLOB * pENVELOPEDKEYBLOB_EPK = NULL;	// 外部公钥加密数字信封

	pENVELOPEDKEYBLOB_IPK = (OPST_SKF_ENVELOPEDKEYBLOB *)pvENVELOPEDKEYBLOB_IPK;
	pENVELOPEDKEYBLOB_EPK = (OPST_SKF_ENVELOPEDKEYBLOB *)pvENVELOPEDKEYBLOB_EPK;

	if (pENVELOPEDKEYBLOB_IPK && pENVELOPEDKEYBLOB_EPK)
	{
		
	}
	else
	{
		uiRes = PCI_PARAM_ERR;
		goto err;
	}

	// 初始化外部公钥
	stECC_EPK.bits = ECCref_MAX_BITS;
	memcpy(stECC_EPK.x, pbPubkeyX, ECCref_MAX_LEN);
	memcpy(stECC_EPK.y, pbPubkeyY, ECCref_MAX_LEN);

	// 设置
	// 初始化C1，C2，C3
	stECCCipherIPK.clength = pENVELOPEDKEYBLOB_IPK->ECCCipherBlob.CipherLen ;
	memcpy(stECCCipherIPK.M,pENVELOPEDKEYBLOB_IPK->ECCCipherBlob.HASH,ECCref_MAX_LEN);
	memcpy(stECCCipherIPK.x,pENVELOPEDKEYBLOB_IPK->ECCCipherBlob.XCoordinate + ECCref_MAX_LEN,ECCref_MAX_LEN);
	memcpy(stECCCipherIPK.y,pENVELOPEDKEYBLOB_IPK->ECCCipherBlob.YCoordinate + ECCref_MAX_LEN,ECCref_MAX_LEN);
	memcpy(stECCCipherIPK.C,pENVELOPEDKEYBLOB_IPK->ECCCipherBlob.Cipher,stECCCipherIPK.clength);

	// 数字信封转换（内部转外部）
	uiRes = SDF_ExchangeDigitEnvelopeBaseOnECC(hSessionHandle,PCI_MAIN_KEY_ECC,uiSymAlg,&stECC_EPK,
		&stECCCipherIPK,&stECCCipherEPK);

	if(0 == uiRes)
	{

	}
	else
	{
		goto err;
	}

	// 设置输出数据
	{
		// 设置
		memcpy(pENVELOPEDKEYBLOB_EPK, pENVELOPEDKEYBLOB_IPK , sizeof(OPST_SKF_ENVELOPEDKEYBLOB));

		// 数字信封（密文私钥）
		pENVELOPEDKEYBLOB_IPK->ECCCipherBlob.CipherLen = stECCCipherIPK.clength;
		memcpy(pENVELOPEDKEYBLOB_IPK->ECCCipherBlob.HASH,stECCCipherIPK.M,ECCref_MAX_LEN);
		memcpy(pENVELOPEDKEYBLOB_IPK->ECCCipherBlob.XCoordinate + ECCref_MAX_LEN,stECCCipherIPK.x,ECCref_MAX_LEN);
		memcpy(pENVELOPEDKEYBLOB_IPK->ECCCipherBlob.YCoordinate + ECCref_MAX_LEN,stECCCipherIPK.y,ECCref_MAX_LEN);
		memcpy(pENVELOPEDKEYBLOB_IPK->ECCCipherBlob.Cipher,stECCCipherIPK.C,stECCCipherIPK.clength);

		// 数字信封（密文私钥）
		pENVELOPEDKEYBLOB_EPK->ECCCipherBlob.CipherLen = stECCCipherEPK.clength;
		memcpy(pENVELOPEDKEYBLOB_EPK->ECCCipherBlob.HASH,stECCCipherEPK.M,ECCref_MAX_LEN);
		memcpy(pENVELOPEDKEYBLOB_EPK->ECCCipherBlob.XCoordinate + ECCref_MAX_LEN,stECCCipherEPK.x,ECCref_MAX_LEN);
		memcpy(pENVELOPEDKEYBLOB_EPK->ECCCipherBlob.YCoordinate + ECCref_MAX_LEN,stECCCipherEPK.y,ECCref_MAX_LEN);
		memcpy(pENVELOPEDKEYBLOB_EPK->ECCCipherBlob.Cipher,stECCCipherEPK.C,stECCCipherEPK.clength);
	}
err:

	return uiRes;
}




unsigned int PCI_CheckExistRootSM2Keys(HANDLE hSessionHandle)
{
	unsigned int uiRes = 0;

	SGD_UINT32 uiLen = PCI_ECC_MAX_KEY;
	SGD_UINT32 szState[PCI_ECC_MAX_KEY] = {0};
	
	uiRes = SDF_GetKeyStatus(hSessionHandle, KEY_TYPE_ECC, szState, &uiLen);

	FILE_LOG_STRING(file_log_name,"PCI_CheckExistRootSM2Keys");
	FILE_LOG_NUMBER(file_log_name,szState[0]);
	FILE_LOG_NUMBER(file_log_name,uiRes);

	if (0 == uiRes)
	{
		if (0 != szState[0])
		{
			uiRes = 0;
			FILE_LOG_STRING(file_log_name,"1");
		}
		else
		{
			uiRes = OPE_ERR_PCI_CHECK_ROOTSM2KEY_NOT_EXIST;
			FILE_LOG_STRING(file_log_name,"2");
		}
	}

	return uiRes;
}

unsigned int PCI_CheckNotExistRootSM2Keys(HANDLE hSessionHandle)
{
	unsigned int uiRes = 0;

	SGD_UINT32 uiLen = PCI_ECC_MAX_KEY;
	SGD_UINT32 szState[PCI_ECC_MAX_KEY] = {0};

	uiRes = SDF_GetKeyStatus(hSessionHandle, KEY_TYPE_ECC, szState, &uiLen);

	FILE_LOG_STRING(file_log_name,"PCI_CheckNotExistRootSM2Keys");
	FILE_LOG_NUMBER(file_log_name,szState[0]);
	FILE_LOG_NUMBER(file_log_name,uiRes);


	if (0 == uiRes)
	{
		if (0 != szState[0])
		{
			uiRes = OPE_ERR_PCI_CHECK_ROOTSM2KEY_EXIST;
			FILE_LOG_STRING(file_log_name,"3");
		}
		else
		{
			uiRes = 0;
			FILE_LOG_STRING(file_log_name,"4");
		}
	}

	return uiRes;
}

unsigned int PCI_GenRootSM2Keys(HANDLE hSessionHandle,unsigned char *pbCipherValue, unsigned int * puiCipherLen)
{
	unsigned int uiRes = 0;

	ECCrefPublicKey pucPublicKey;
	ECCrefPrivateKey pucPrivateKey;

	uiRes = SWCSM_GenerateECCKeyPair(hSessionHandle, PCI_MAIN_KEY_ECC_EX);
	uiRes = SWCSM_GenerateECCKeyPair(hSessionHandle, PCI_MAIN_KEY_ECC_SIGN);
#if 0
	FILE_LOG_STRING(file_log_name,__FUNCTION__);

	uiRes = SDF_GenerateKeyPair_ECC(
		hSessionHandle, 
		KEY_TYPE_ECC,
		256,
		&pucPublicKey,
		&pucPrivateKey);

	if (0 == uiRes)
	{
		memcpy(aCipherValue, &pucPublicKey, sizeof(ECCrefPublicKey));
		memcpy(aCipherValue +  sizeof(ECCrefPublicKey), &pucPrivateKey,sizeof(ECCrefPrivateKey));

		*aCipherLen = sizeof(ECCrefPublicKey) + sizeof(ECCrefPrivateKey);
	}
	else
	{
		goto err;
	}

	//uiRes = SWCSM_ImportECCKeyPair(hSessionHandle,PCI_MAIN_KEY, &pucPublicKey,
	//	&pucPrivateKey);
	FILE_LOG_NUMBER(file_log_name,uiRes);
	FILE_LOG_NUMBER(file_log_name,*aCipherLen);
	FILE_LOG_HEX(file_log_name,aCipherValue,*aCipherLen);
#endif

err:

	return uiRes;
}

unsigned int PCI_GenRootSymKey(HANDLE hSessionHandle,unsigned char *aCipherValue, unsigned int * aCipherLen)
{
	unsigned int uiRes = 0;

	ECCrefPublicKey pucPublicKey;
	ECCrefPrivateKey pucPrivateKey;

	//uiRes = SWCSM_GenerateECCKeyPair(hSessionHandle, PCI_MAIN_KEY);

	FILE_LOG_STRING(file_log_name,__FUNCTION__);

	uiRes = SDF_GenerateKeyPair_ECC(
		hSessionHandle, 
		KEY_TYPE_ECC,
		256,
		&pucPublicKey,
		&pucPrivateKey);

	if (0 == uiRes)
	{
		memcpy(aCipherValue, &pucPublicKey, sizeof(ECCrefPublicKey));
		memcpy(aCipherValue +  sizeof(ECCrefPublicKey), &pucPrivateKey,sizeof(ECCrefPrivateKey));

		*aCipherLen = sizeof(ECCrefPublicKey) + sizeof(ECCrefPrivateKey);
	}
	else
	{
		goto err;
	}

	//uiRes = SWCSM_ImportECCKeyPair(hSessionHandle,PCI_MAIN_KEY, &pucPublicKey,
	//	&pucPrivateKey);
	FILE_LOG_NUMBER(file_log_name,uiRes);
	FILE_LOG_NUMBER(file_log_name,*aCipherLen);
	FILE_LOG_HEX(file_log_name,aCipherValue,*aCipherLen);

err:

	return uiRes;
}

unsigned int PCI_GenSM2Keys(HANDLE hSessionHandle,unsigned char *pbCipherValue, unsigned int * puiCipherLen)
{
	unsigned int uiRes = 0;

	ECCrefPublicKey pucPublicKey;
	ECCrefPrivateKey pucPrivateKey;

	uiRes = SDF_GenerateKeyPair_ECC(
		hSessionHandle, 
		KEY_TYPE_ECC,
		256,
		&pucPublicKey,
		&pucPrivateKey);

	memcpy(pbCipherValue, &pucPublicKey, sizeof(ECCrefPublicKey));
	memcpy(pbCipherValue +  sizeof(ECCrefPublicKey), &pucPrivateKey,sizeof(ECCrefPrivateKey));

	*puiCipherLen = sizeof(ECCrefPublicKey) + sizeof(ECCrefPrivateKey);

	return uiRes;
}


unsigned int PCI_SignWithRootSM2Keys(HANDLE hSessionHandle, 
	const unsigned char * pbPW, unsigned int uiPWLen,
	const unsigned char *pbInValue, unsigned int uiInLen,unsigned int uiAlg,
	unsigned char * pbSigValue, unsigned int * puiSigLen
	)
{
	unsigned int uiRes = 0;

	ECCSignature ecSig = {0};

	//uiRes = SDF_GetPrivateKeyAccessRight(hSessionHandle,PCI_MAIN_KEY,apw_value,apw_len);

	uiRes = SDF_InternalSign_ECC(
		hSessionHandle,
		PCI_MAIN_KEY_ECC,
		(SGD_UCHAR *)pbInValue,
		uiInLen,
		&ecSig);

	//uiRes = SDF_ReleasePrivateKeyAccessRight (hSessionHandle, PCI_MAIN_KEY);

	if (NULL == pbSigValue)
	{
		* puiSigLen = 2 * ECCref_MAX_LEN;
	}
	else if (* puiSigLen < 2 * ECCref_MAX_LEN)
	{
		* puiSigLen = 2 * ECCref_MAX_LEN;
		uiRes = OPE_ERR_NOT_ENOUGH_MEMORY;
	}
	else
	{
		* puiSigLen = 2 * ECCref_MAX_LEN;
		memcpy(pbSigValue ,ecSig.r, ECCref_MAX_LEN);
		memcpy(pbSigValue + ECCref_MAX_LEN,ecSig.s, ECCref_MAX_LEN);
	}

	return uiRes;
}

unsigned int PCI_SignWithSM2Keys(HANDLE hSessionHandle,
	const unsigned char * pbPrivateKey, unsigned int uiPrivateKeyLen,
	const unsigned char * pbInValue, unsigned int uiInLen,
	unsigned char * pbSigValue, unsigned int * puiSigLen
	)
{
	unsigned int uiRes = 0;

	ECCrefPrivateKey ecPrvkey = {0};
	ECCSignature ecSig = {0};

	ecPrvkey.bits = ECCref_MAX_BITS;

	memcpy(ecPrvkey.D, pbPrivateKey, uiPrivateKeyLen);

	uiRes = SDF_ExternalSign_ECC(
		hSessionHandle,
		SGD_SM2_1,
		&ecPrvkey,
		(SGD_UCHAR *)pbInValue,
		uiInLen,
		&ecSig);
	if (NULL == pbSigValue)
	{
		* puiSigLen = 2 * ECCref_MAX_LEN;
	}
	else if (* puiSigLen < 2 * ECCref_MAX_LEN)
	{
		uiRes = OPE_ERR_NOT_ENOUGH_MEMORY;
		* puiSigLen = 2 * ECCref_MAX_LEN;
	}
	else
	{
		* puiSigLen = 2 * ECCref_MAX_LEN;
		memcpy(pbSigValue ,ecSig.r, ECCref_MAX_BITS);
		memcpy(pbSigValue + ECCref_MAX_BITS,ecSig.s, ECCref_MAX_BITS);
	}

	return uiRes;
}

unsigned int PCI_VerifyWithSM2Keys(HANDLE hSessionHandle,
	const unsigned char * pbPubkeyX, unsigned int uiPubkeyXLen,
	const unsigned char * pbPubkeyY, unsigned int uiPubkeyYLen,
	const unsigned char * pbInValue, unsigned int uiInLen,
	const unsigned char * pbSigValue, unsigned int uiSigLen
	)
{
	unsigned int uiRes = 0;

	ECCrefPublicKey ecPubkey = {0};
	ECCSignature ecSig = {0};

	ecPubkey.bits = ECCref_MAX_BITS;

	memcpy(ecPubkey.x, pbPubkeyX, uiPubkeyXLen);
	memcpy(ecPubkey.y, pbPubkeyY, uiPubkeyYLen);

	memcpy(ecSig.r, pbSigValue, ECCref_MAX_LEN);
	memcpy(ecSig.s, pbSigValue + ECCref_MAX_LEN, ECCref_MAX_LEN);

	uiRes = SDF_ExternalVerify_ECC(
		hSessionHandle,
		SGD_SM2_1,
		&ecPubkey,
		(SGD_UCHAR *)pbInValue,
		uiInLen,
		&ecSig);

	return uiRes;
}

unsigned int	PCI_BackupInit(HANDLE hSessionHandle)
{
	unsigned int	uiRes = 0;

	uiRes = SWCSM_BackupInit(hSessionHandle, SGD_SM1_ECB);

	return uiRes;
}

unsigned int PCI_BackupKeyComponent(HANDLE hSessionHandle, unsigned int uiNumber, 
	const unsigned char *pbPinValue, unsigned int uiPinLen, unsigned int *puiTrials)
{
	unsigned int	uiRes = 0;

	if ( (uiNumber < 1 || uiNumber > 3) || 8 != uiPinLen)
	{
		return PCI_PARAM_ERR;
	}
	
	uiRes = SWCSM_BackupExportKeyComponent(hSessionHandle, uiNumber, (SGD_UINT8 *)pbPinValue);
	if ( 0x01036200 == uiRes )
	{
		uiRes = PCI_CARD_NO_FIND_IC;
	}
	else if ( ((SWR_CARD_READER_PIN_ERROR) >> 8) == (uiRes >> 8) )	// IC卡口令错误
	{
		*puiTrials = uiRes & 0x0F;
		uiRes = PCI_CARD_IC_PIN_ERR;
	}
	else if ( 0x01036983 == uiRes )	// IC卡已锁死
	{
		uiRes = PCI_CARD_IC_PIN_LOCK_ERR;
	}
	else if( 0x01036400 == uiRes )
	{
		uiRes = PCI_CARD_INSERT_ERR;
	}

	return uiRes;
}


unsigned int PCI_BackupECC(HANDLE hSessionHandle, unsigned int bFlagSign,
	unsigned char *pbCipherValue, unsigned int *puiCipherLen)
{
	unsigned int uiRes = 0;

	SGD_UINT8 pbCipher[256] = {0};

	SGD_UINT32 uiSM2Bits = 256;

	SGD_UINT32 uiSM2Len = 256;

	unsigned int uiKeyIndex = bFlagSign ? (PCI_MAIN_KEY_ECC_SIGN):(PCI_MAIN_KEY_ECC_EX);

	if ( 0 == puiCipherLen)
	{
		return PCI_PARAM_ERR;
	}

	// 主密钥
	uiRes = SWCSM_BackupExportECCKey(hSessionHandle, PCI_MAIN_KEY_ECC_SIGN, &uiSM2Bits, pbCipher, &uiSM2Len);
	if (uiRes)
	{
		return uiRes;
	} 

	uiRes = SWCSM_BackupExportECCKey(hSessionHandle, PCI_MAIN_KEY_ECC_EX, &uiSM2Bits, pbCipher + uiSM2Bits/8 * 3, &uiSM2Len);
	if (uiRes)
	{
		return uiRes;
	} 

	if (NULL == pbCipherValue || *puiCipherLen < uiSM2Bits/8 * 3 * 2)
	{
		*puiCipherLen = uiSM2Bits/8 * 3 * 2;
	}
	else
	{
		memcpy( pbCipherValue, pbCipher, uiSM2Bits/8 * 3 * 2);
		*puiCipherLen = uiSM2Bits/8 * 3 * 2;
	}

	return uiRes;
}

unsigned int	PCI_BackupFinal(HANDLE hSessionHandle)
{
	unsigned int	uiRes = 0;

	uiRes = SWCSM_BackupFinal(hSessionHandle);

	return uiRes;
}



unsigned int	PCI_RestoreInit(HANDLE hSessionHandle)
{
	unsigned int	uiRes = 0;

	uiRes = SWCSM_RestoreInit(hSessionHandle, SGD_SM1_ECB);

	return uiRes;
}

unsigned int PCI_RestoreKeyComponent(HANDLE hSessionHandle, 
	const unsigned char *pbPinValue, unsigned int uiPinLen, unsigned int * puiTrials)
{
	unsigned int	uiRes = 0;

	if ( 8 != uiPinLen )
	{
		return PCI_PARAM_ERR;
	}

	uiRes = SWCSM_RestoreImportKeyComponent(hSessionHandle, (SGD_UINT8 *)pbPinValue);
	if ( 0x01036200 == uiRes )
	{
		uiRes = PCI_CARD_NO_FIND_IC;
	}
	else if ( ((SWR_CARD_READER_PIN_ERROR) >> 8) == (uiRes >> 8) )	// IC卡口令错误
	{
		*puiTrials = uiRes & 0x0F;
		uiRes = PCI_CARD_IC_PIN_ERR;
	}
	else if ( 0x01036983 == uiRes )	// IC卡已锁死
	{
		uiRes = PCI_CARD_IC_PIN_LOCK_ERR;
	}
	else if( 0x01036400 == uiRes )
	{
		uiRes = PCI_CARD_INSERT_ERR;
	}

	return uiRes;
}


unsigned int PCI_RestoreECC(HANDLE hSessionHandle, unsigned int bFlagSign,
	const unsigned char *pbCipherValue, unsigned int uiCipherLen)
{
	unsigned int	uiRes = 0;
	unsigned int	uiTmpLen = 0;

	SGD_UINT32 uiSM2Bits = 256;

	unsigned int uiKeyIndex = bFlagSign ? (PCI_MAIN_KEY_ECC_SIGN):(PCI_MAIN_KEY_ECC_EX);

	if ( NULL == pbCipherValue)
	{
		return PCI_PARAM_ERR;
	}
	if( uiCipherLen != uiSM2Bits / 8 * 2 * 3)
	{
		return PCI_PARAM_ERR;
	}

	uiRes = SWCSM_RestoreImportECCKey(hSessionHandle, PCI_MAIN_KEY_ECC_SIGN,
		uiSM2Bits,pbCipherValue,uiCipherLen/2);
	if (uiRes)
	{
		return uiRes;
	}

	uiRes = SWCSM_RestoreImportECCKey(hSessionHandle, PCI_MAIN_KEY_ECC_EX,
		uiSM2Bits,pbCipherValue + uiCipherLen/2,uiCipherLen/2);
	if (uiRes)
	{
		return uiRes;
	}

	return uiRes;
}

unsigned int	PCI_RestoreFinal(HANDLE hSessionHandle)
{
	unsigned int	uiRes = 0;

	uiRes = SWCSM_RestoreFinal(hSessionHandle);

	if (0 != uiRes)
	{
		goto err;
	}

err:

	return uiRes;
}


unsigned int PCI_ExportRootSM2Keys(HANDLE hSessionHandle, unsigned char *pbPubKeyX, unsigned int *puiPubKeyLenX, unsigned char *pbPubKeyY, unsigned int *puiPubKeyLenY)
{
	unsigned int	uiRes = 0;

	ECCrefPublicKey pubSign = {0};

	uiRes = SDF_ExportSignPublicKey_ECC(hSessionHandle, PCI_MAIN_KEY_ECC, &pubSign);

	if (0 != uiRes)
	{
		goto err;
	}

	if (NULL == pbPubKeyX || NULL == pbPubKeyY)
	{
		*puiPubKeyLenX = ECCref_MAX_LEN;
		*puiPubKeyLenY = ECCref_MAX_LEN;
	}
	else if (*puiPubKeyLenX < ECCref_MAX_LEN || *puiPubKeyLenY < ECCref_MAX_LEN)
	{
		uiRes = OPE_ERR_NOT_ENOUGH_MEMORY;
	}
	else
	{
		*puiPubKeyLenX = ECCref_MAX_LEN;
		*puiPubKeyLenY = ECCref_MAX_LEN;

		memcpy(pbPubKeyX,pubSign.x, ECCref_MAX_LEN);
		memcpy(pbPubKeyY,pubSign.y, ECCref_MAX_LEN);
	}

err:

	return uiRes;
}
