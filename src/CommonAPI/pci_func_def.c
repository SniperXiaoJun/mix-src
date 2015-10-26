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


unsigned long	PCI_Open(HANDLE *phPCIHandle, HANDLE *phSessionHandle)
{
	unsigned long	ulResult = 0;

	SGD_HANDLE hDeviceHandle = NULL;
	SGD_HANDLE hSessionHandle = NULL;

#ifndef	PCI_TEST	

	if ( NULL == phPCIHandle || NULL == phSessionHandle)
	{
		return PCI_PARAM_ERR;
	}

	ulResult = SDF_OpenDevice(&hDeviceHandle);
	if(ulResult != SDR_OK)
	{
		return ulResult;
	}

	ulResult = SDF_OpenSession(hDeviceHandle, &hSessionHandle);
	if(ulResult != SDR_OK)
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

	return ulResult;
}


unsigned long	PCI_Close(HANDLE hPCIHandle, HANDLE hSessionHandle)
{
	unsigned long	ulResult = 0;


#ifndef	PCI_TEST

	if(hSessionHandle != NULL)
	{
		ulResult = SDF_CloseSession(hSessionHandle);
	}

	if(hPCIHandle != NULL)
	{
		ulResult = SDF_CloseDevice(hPCIHandle);
	}

#else

#endif 

	return ulResult;
}


unsigned long PCI_ICLogin(HANDLE hSessionHandle,
	const unsigned char* pbPINValue, unsigned long ulPINLen , 
	unsigned long *pulUserID, unsigned long *pulTrials)
{
	unsigned long	ulResult = 0;

	if ( NULL == pbPINValue || 8 != ulPINLen || NULL == pulUserID || NULL == pulTrials )
	{
		return PCI_PARAM_ERR;
	}

	ulResult = SWCSM_Login(hSessionHandle,(SGD_UCHAR *)pbPINValue,(SGD_UINT32 *)pulUserID);
	if ( 0x01036200 == ulResult )
	{
		ulResult = PCI_CARD_NO_FIND_IC;
	}
	else if ( ((SWR_CARD_READER_PIN_ERROR) >> 8) == (ulResult >> 8) )	// IC卡口令错误
	{
		*pulTrials = ulResult & 0x0F;
		ulResult = PCI_CARD_IC_PIN_ERR;
	}
	else if ( 0x01036983 == ulResult )	// IC卡已锁死
	{
		ulResult = PCI_CARD_IC_PIN_LOCK_ERR;
	}
	else if( 0x01036400 == ulResult )
	{
		ulResult = PCI_CARD_INSERT_ERR;
	}

	return ulResult;
}


unsigned long PCI_ICLogout(HANDLE hSessionHandle, unsigned long ulUserID)
{
	unsigned long	ulResult = 0;

#ifndef	PCI_TEST
	ulResult = SWCSM_Logout(hSessionHandle, ulUserID);
#else

#endif

	return ulResult;
}


unsigned long PCI_GenExportSM2EnvelopedKey(HANDLE hSessionHandle, unsigned char *pbPubkeyX,unsigned char *pbPubkeyY,
	void * pvENVELOPEDKEYBLOB_IPK, void * pvENVELOPEDKEYBLOB_EPK)
{
	unsigned long	ulResult = 0;

	ECCCipher stECCCipherIPK = {0};					// 内部公钥加密密文
	ECCCipher stECCCipherEPK = {0};					// 外部公钥加密密文

	HANDLE hKEY = 0;								// 密钥加密密钥句柄
	ECCrefPublicKey  stECC_EPK =    {0};			// ECC外部加密公钥
	ECCrefPublicKey  stECC_PK_Gen = {0};			// ECC生成钥（待生成）
	ECCrefPrivateKey stECC_SK_Gen = {0};			// ECC生成密钥（待生成）
	unsigned int ulSymAlg = SGD_SM1_ECB;			// 密钥加密密钥对称算法
	unsigned int ulEnPrivakeyLen = ECCref_MAX_LEN;	// 密文私钥长度
	unsigned char cbEnPrivakey[ECCref_MAX_LEN] = {0};// 密文私钥
	unsigned int ulSKBitLen = 128;	// 加密私钥长度
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
		ulResult = PCI_PARAM_ERR;
		goto err;
	}

	// 初始化外部公钥
	stECC_EPK.bits = ECCref_MAX_BITS;
	memcpy(stECC_EPK.x, pbPubkeyX, ECCref_MAX_LEN);
	memcpy(stECC_EPK.y, pbPubkeyY, ECCref_MAX_LEN);

	// 生成ECC密钥对
	ulResult = SDF_GenerateKeyPair_ECC(
		hSessionHandle, 
		KEY_TYPE_ECC,
		ECCref_MAX_BITS,
		&stECC_PK_Gen,
		&stECC_SK_Gen);

	if (0 == ulResult)
	{

	}
	else
	{
		goto err;
	}

	// 生成密钥加密密钥（外部）
	//ulResult = SDF_GenerateKeyWithEPK_ECC (
	//	hSessionHandle, 
	//	ulSKBitLen,
	//	ulSymAlg,
	//	&stECC_EPK,
	//	&stECCCipherEPK,
	//	&hKEY);

	// 生成密钥加密密钥(内部)
	ulResult = SDF_GenerateKeyWithIPK_ECC (
		hSessionHandle, 
		PCI_MAIN_KEY_ECC,
		ulSKBitLen,
		&stECCCipherIPK,
		&hKEY);

	if (0 == ulResult)
	{

	}
	else
	{
		goto err;
	}

	// 数字信封转换（内部转外部）
	ulResult = SDF_ExchangeDigitEnvelopeBaseOnECC(hSessionHandle,PCI_MAIN_KEY_ECC,KEY_TYPE_ECC,&stECC_EPK,&stECCCipherIPK,&stECCCipherEPK);

	if(0 == ulResult)
	{

	}
	else
	{
		goto err;
	}

	// 对私钥进行加密
	ulResult = SDF_Encrypt(hSessionHandle,hKEY,ulSymAlg,NULL,
		stECC_SK_Gen.D,ECCref_MAX_LEN,
		cbEnPrivakey,&ulEnPrivakeyLen);

	if (0 == ulResult)
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
		pENVELOPEDKEYBLOB_IPK->ulBits = ECC_MAX_XCOORDINATE_BITS_LEN / 2;

		// 算法
		pENVELOPEDKEYBLOB_IPK->ulSymmAlgID = ulSymAlg;

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

	return ulResult;
}


unsigned long PCI_RestoreExportSM2EnvelopedKey(HANDLE hSessionHandle, unsigned char *pbPubkeyX,unsigned char *pbPubkeyY, 
	void * pvENVELOPEDKEYBLOB_IPK, void * pvENVELOPEDKEYBLOB_EPK)
{
	unsigned long	ulResult = 0;

	ECCCipher stECCCipherIPK = {0};					// 内部公钥加密密文
	ECCCipher stECCCipherEPK = {0};					// 外部公钥加密密文

	HANDLE hKEY = 0;								// 密钥加密密钥句柄
	ECCrefPublicKey  stECC_EPK =    {0};			// ECC外部加密公钥
	unsigned int ulSymAlg = SGD_SM1_ECB;			// 密钥加密密钥对称算法
	unsigned int ulSKBitLen = 128;	// 加密私钥长度
	OPST_SKF_ENVELOPEDKEYBLOB * pENVELOPEDKEYBLOB_IPK = NULL;	// 内部公钥加密数字信封
	OPST_SKF_ENVELOPEDKEYBLOB * pENVELOPEDKEYBLOB_EPK = NULL;	// 外部公钥加密数字信封

	pENVELOPEDKEYBLOB_IPK = (OPST_SKF_ENVELOPEDKEYBLOB *)pvENVELOPEDKEYBLOB_IPK;
	pENVELOPEDKEYBLOB_EPK = (OPST_SKF_ENVELOPEDKEYBLOB *)pvENVELOPEDKEYBLOB_EPK;

	if (pENVELOPEDKEYBLOB_IPK && pENVELOPEDKEYBLOB_EPK)
	{
		
	}
	else
	{
		ulResult = PCI_PARAM_ERR;
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
	ulResult = SDF_ExchangeDigitEnvelopeBaseOnECC(hSessionHandle,PCI_MAIN_KEY_ECC,ulSymAlg,&stECC_EPK,
		&stECCCipherIPK,&stECCCipherEPK);

	if(0 == ulResult)
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

	return ulResult;
}




unsigned long PCI_CheckExistRootSM2Keys(HANDLE hSessionHandle)
{
	unsigned long ulResult = 0;

	SGD_UINT32 ulLen = PCI_ECC_MAX_KEY;
	SGD_UINT32 szState[PCI_ECC_MAX_KEY] = {0};
	
	ulResult = SDF_GetKeyStatus(hSessionHandle, KEY_TYPE_ECC, szState, &ulLen);

	FILE_LOG_STRING(file_log_name,"PCI_CheckExistRootSM2Keys");
	FILE_LOG_NUMBER(file_log_name,szState[0]);
	FILE_LOG_NUMBER(file_log_name,ulResult);

	if (0 == ulResult)
	{
		if (0 != szState[0])
		{
			ulResult = 0;
			FILE_LOG_STRING(file_log_name,"1");
		}
		else
		{
			ulResult = OPE_ERR_PCI_CHECK_ROOTSM2KEY_NOT_EXIST;
			FILE_LOG_STRING(file_log_name,"2");
		}
	}

	return ulResult;
}

unsigned long PCI_CheckNotExistRootSM2Keys(HANDLE hSessionHandle)
{
	unsigned long ulResult = 0;

	SGD_UINT32 ulLen = PCI_ECC_MAX_KEY;
	SGD_UINT32 szState[PCI_ECC_MAX_KEY] = {0};

	ulResult = SDF_GetKeyStatus(hSessionHandle, KEY_TYPE_ECC, szState, &ulLen);

	FILE_LOG_STRING(file_log_name,"PCI_CheckNotExistRootSM2Keys");
	FILE_LOG_NUMBER(file_log_name,szState[0]);
	FILE_LOG_NUMBER(file_log_name,ulResult);


	if (0 == ulResult)
	{
		if (0 != szState[0])
		{
			ulResult = OPE_ERR_PCI_CHECK_ROOTSM2KEY_EXIST;
			FILE_LOG_STRING(file_log_name,"3");
		}
		else
		{
			ulResult = 0;
			FILE_LOG_STRING(file_log_name,"4");
		}
	}

	return ulResult;
}

unsigned long PCI_GenRootSM2Keys(HANDLE hSessionHandle,unsigned char *pbCipherValue, unsigned long * pulCipherLen)
{
	unsigned long ulResult = 0;

	ECCrefPublicKey pucPublicKey;
	ECCrefPrivateKey pucPrivateKey;

	ulResult = SWCSM_GenerateECCKeyPair(hSessionHandle, PCI_MAIN_KEY_ECC_EX);
	ulResult = SWCSM_GenerateECCKeyPair(hSessionHandle, PCI_MAIN_KEY_ECC_SIGN);
#if 0
	FILE_LOG_STRING(file_log_name,__FUNCTION__);

	ulResult = SDF_GenerateKeyPair_ECC(
		hSessionHandle, 
		KEY_TYPE_ECC,
		256,
		&pucPublicKey,
		&pucPrivateKey);

	if (0 == ulResult)
	{
		memcpy(aCipherValue, &pucPublicKey, sizeof(ECCrefPublicKey));
		memcpy(aCipherValue +  sizeof(ECCrefPublicKey), &pucPrivateKey,sizeof(ECCrefPrivateKey));

		*aCipherLen = sizeof(ECCrefPublicKey) + sizeof(ECCrefPrivateKey);
	}
	else
	{
		goto err;
	}

	//ulResult = SWCSM_ImportECCKeyPair(hSessionHandle,PCI_MAIN_KEY, &pucPublicKey,
	//	&pucPrivateKey);
	FILE_LOG_NUMBER(file_log_name,ulResult);
	FILE_LOG_NUMBER(file_log_name,*aCipherLen);
	FILE_LOG_HEX(file_log_name,aCipherValue,*aCipherLen);
#endif

err:

	return ulResult;
}

unsigned long PCI_GenRootSymKey(HANDLE hSessionHandle,unsigned char *aCipherValue, unsigned long * aCipherLen)
{
	unsigned long ulResult = 0;

	ECCrefPublicKey pucPublicKey;
	ECCrefPrivateKey pucPrivateKey;

	//ulResult = SWCSM_GenerateECCKeyPair(hSessionHandle, PCI_MAIN_KEY);

	FILE_LOG_STRING(file_log_name,__FUNCTION__);

	ulResult = SDF_GenerateKeyPair_ECC(
		hSessionHandle, 
		KEY_TYPE_ECC,
		256,
		&pucPublicKey,
		&pucPrivateKey);

	if (0 == ulResult)
	{
		memcpy(aCipherValue, &pucPublicKey, sizeof(ECCrefPublicKey));
		memcpy(aCipherValue +  sizeof(ECCrefPublicKey), &pucPrivateKey,sizeof(ECCrefPrivateKey));

		*aCipherLen = sizeof(ECCrefPublicKey) + sizeof(ECCrefPrivateKey);
	}
	else
	{
		goto err;
	}

	//ulResult = SWCSM_ImportECCKeyPair(hSessionHandle,PCI_MAIN_KEY, &pucPublicKey,
	//	&pucPrivateKey);
	FILE_LOG_NUMBER(file_log_name,ulResult);
	FILE_LOG_NUMBER(file_log_name,*aCipherLen);
	FILE_LOG_HEX(file_log_name,aCipherValue,*aCipherLen);

err:

	return ulResult;
}

unsigned long PCI_GenSM2Keys(HANDLE hSessionHandle,unsigned char *pbCipherValue, unsigned long * pulCipherLen)
{
	unsigned long ulResult = 0;

	ECCrefPublicKey pucPublicKey;
	ECCrefPrivateKey pucPrivateKey;

	ulResult = SDF_GenerateKeyPair_ECC(
		hSessionHandle, 
		KEY_TYPE_ECC,
		256,
		&pucPublicKey,
		&pucPrivateKey);

	memcpy(pbCipherValue, &pucPublicKey, sizeof(ECCrefPublicKey));
	memcpy(pbCipherValue +  sizeof(ECCrefPublicKey), &pucPrivateKey,sizeof(ECCrefPrivateKey));

	*pulCipherLen = sizeof(ECCrefPublicKey) + sizeof(ECCrefPrivateKey);

	return ulResult;
}


unsigned long PCI_SignWithRootSM2Keys(HANDLE hSessionHandle, 
	const unsigned char * pbPW, unsigned long ulPWLen,
	const unsigned char *pbInValue, unsigned long ulInLen,unsigned long ulAlg,
	unsigned char * pbSigValue, unsigned long * pulSigLen
	)
{
	unsigned long ulResult = 0;

	ECCSignature ecSig = {0};

	//ulResult = SDF_GetPrivateKeyAccessRight(hSessionHandle,PCI_MAIN_KEY,apw_value,apw_len);

	ulResult = SDF_InternalSign_ECC(
		hSessionHandle,
		PCI_MAIN_KEY_ECC,
		(SGD_UCHAR *)pbInValue,
		ulInLen,
		&ecSig);

	//ulResult = SDF_ReleasePrivateKeyAccessRight (hSessionHandle, PCI_MAIN_KEY);

	if (NULL == pbSigValue)
	{
		* pulSigLen = 2 * ECCref_MAX_LEN;
	}
	else if (* pulSigLen < 2 * ECCref_MAX_LEN)
	{
		* pulSigLen = 2 * ECCref_MAX_LEN;
		ulResult = OPE_ERR_NOT_ENOUGH_MEMORY;
	}
	else
	{
		* pulSigLen = 2 * ECCref_MAX_LEN;
		memcpy(pbSigValue ,ecSig.r, ECCref_MAX_LEN);
		memcpy(pbSigValue + ECCref_MAX_LEN,ecSig.s, ECCref_MAX_LEN);
	}

	return ulResult;
}

unsigned long PCI_SignWithSM2Keys(HANDLE hSessionHandle,
	const unsigned char * pbPrivateKey, unsigned long ulPrivateKeyLen,
	const unsigned char * pbInValue, unsigned long ulInLen,
	unsigned char * pbSigValue, unsigned long * pulSigLen
	)
{
	unsigned long ulResult = 0;

	ECCrefPrivateKey ecPrvkey = {0};
	ECCSignature ecSig = {0};

	ecPrvkey.bits = ECCref_MAX_BITS;

	memcpy(ecPrvkey.D, pbPrivateKey, ulPrivateKeyLen);

	ulResult = SDF_ExternalSign_ECC(
		hSessionHandle,
		SGD_SM2_1,
		&ecPrvkey,
		(SGD_UCHAR *)pbInValue,
		ulInLen,
		&ecSig);
	if (NULL == pbSigValue)
	{
		* pulSigLen = 2 * ECCref_MAX_LEN;
	}
	else if (* pulSigLen < 2 * ECCref_MAX_LEN)
	{
		ulResult = OPE_ERR_NOT_ENOUGH_MEMORY;
		* pulSigLen = 2 * ECCref_MAX_LEN;
	}
	else
	{
		* pulSigLen = 2 * ECCref_MAX_LEN;
		memcpy(pbSigValue ,ecSig.r, ECCref_MAX_BITS);
		memcpy(pbSigValue + ECCref_MAX_BITS,ecSig.s, ECCref_MAX_BITS);
	}

	return ulResult;
}

unsigned long PCI_VerifyWithSM2Keys(HANDLE hSessionHandle,
	const unsigned char * pbPubkeyX, unsigned long ulPubkeyXLen,
	const unsigned char * pbPubkeyY, unsigned long ulPubkeyYLen,
	const unsigned char * pbInValue, unsigned long ulInLen,
	const unsigned char * pbSigValue, unsigned long ulSigLen
	)
{
	unsigned long ulResult = 0;

	ECCrefPublicKey ecPubkey = {0};
	ECCSignature ecSig = {0};

	ecPubkey.bits = ECCref_MAX_BITS;

	memcpy(ecPubkey.x, pbPubkeyX, ulPubkeyXLen);
	memcpy(ecPubkey.y, pbPubkeyY, ulPubkeyYLen);

	memcpy(ecSig.r, pbSigValue, ECCref_MAX_LEN);
	memcpy(ecSig.s, pbSigValue + ECCref_MAX_LEN, ECCref_MAX_LEN);

	ulResult = SDF_ExternalVerify_ECC(
		hSessionHandle,
		SGD_SM2_1,
		&ecPubkey,
		(SGD_UCHAR *)pbInValue,
		ulInLen,
		&ecSig);

	return ulResult;
}

unsigned long	PCI_BackupInit(HANDLE hSessionHandle)
{
	unsigned long	ulResult = 0;

	ulResult = SWCSM_BackupInit(hSessionHandle, SGD_SM1_ECB);

	return ulResult;
}

unsigned long PCI_BackupKeyComponent(HANDLE hSessionHandle, unsigned long ulNumber, 
	const unsigned char *pbPinValue, unsigned long ulPinLen, unsigned long *pulTrials)
{
	unsigned long	ulResult = 0;

	if ( (ulNumber < 1 || ulNumber > 3) || 8 != ulPinLen)
	{
		return PCI_PARAM_ERR;
	}
	
	ulResult = SWCSM_BackupExportKeyComponent(hSessionHandle, ulNumber, (SGD_UINT8 *)pbPinValue);
	if ( 0x01036200 == ulResult )
	{
		ulResult = PCI_CARD_NO_FIND_IC;
	}
	else if ( ((SWR_CARD_READER_PIN_ERROR) >> 8) == (ulResult >> 8) )	// IC卡口令错误
	{
		*pulTrials = ulResult & 0x0F;
		ulResult = PCI_CARD_IC_PIN_ERR;
	}
	else if ( 0x01036983 == ulResult )	// IC卡已锁死
	{
		ulResult = PCI_CARD_IC_PIN_LOCK_ERR;
	}
	else if( 0x01036400 == ulResult )
	{
		ulResult = PCI_CARD_INSERT_ERR;
	}

	return ulResult;
}


unsigned long PCI_BackupECC(HANDLE hSessionHandle, unsigned long bFlagSign,
	unsigned char *pbCipherValue, unsigned long *pulCipherLen)
{
	unsigned long ulResult = 0;

	SGD_UINT8 pbCipher[256] = {0};

	SGD_UINT32 ulSM2Bits = 256;

	SGD_UINT32 ulSM2Len = 256;

	unsigned long ulKeyIndex = bFlagSign ? (PCI_MAIN_KEY_ECC_SIGN):(PCI_MAIN_KEY_ECC_EX);

	if ( 0 == pulCipherLen)
	{
		return PCI_PARAM_ERR;
	}

	// 主密钥
	ulResult = SWCSM_BackupExportECCKey(hSessionHandle, PCI_MAIN_KEY_ECC_SIGN, &ulSM2Bits, pbCipher, &ulSM2Len);
	if (ulResult)
	{
		return ulResult;
	} 

	ulResult = SWCSM_BackupExportECCKey(hSessionHandle, PCI_MAIN_KEY_ECC_EX, &ulSM2Bits, pbCipher + ulSM2Bits/8 * 3, &ulSM2Len);
	if (ulResult)
	{
		return ulResult;
	} 

	if (NULL == pbCipherValue || *pulCipherLen < ulSM2Bits/8 * 3 * 2)
	{
		*pulCipherLen = ulSM2Bits/8 * 3 * 2;
	}
	else
	{
		memcpy( pbCipherValue, pbCipher, ulSM2Bits/8 * 3 * 2);
		*pulCipherLen = ulSM2Bits/8 * 3 * 2;
	}

	return ulResult;
}

unsigned long	PCI_BackupFinal(HANDLE hSessionHandle)
{
	unsigned long	ulResult = 0;

	ulResult = SWCSM_BackupFinal(hSessionHandle);

	return ulResult;
}



unsigned long	PCI_RestoreInit(HANDLE hSessionHandle)
{
	unsigned long	ulResult = 0;

	ulResult = SWCSM_RestoreInit(hSessionHandle, SGD_SM1_ECB);

	return ulResult;
}

unsigned long PCI_RestoreKeyComponent(HANDLE hSessionHandle, 
	const unsigned char *pbPinValue, unsigned long ulPinLen, unsigned long * pulTrials)
{
	unsigned long	ulResult = 0;

	if ( 8 != ulPinLen )
	{
		return PCI_PARAM_ERR;
	}

	ulResult = SWCSM_RestoreImportKeyComponent(hSessionHandle, (SGD_UINT8 *)pbPinValue);
	if ( 0x01036200 == ulResult )
	{
		ulResult = PCI_CARD_NO_FIND_IC;
	}
	else if ( ((SWR_CARD_READER_PIN_ERROR) >> 8) == (ulResult >> 8) )	// IC卡口令错误
	{
		*pulTrials = ulResult & 0x0F;
		ulResult = PCI_CARD_IC_PIN_ERR;
	}
	else if ( 0x01036983 == ulResult )	// IC卡已锁死
	{
		ulResult = PCI_CARD_IC_PIN_LOCK_ERR;
	}
	else if( 0x01036400 == ulResult )
	{
		ulResult = PCI_CARD_INSERT_ERR;
	}

	return ulResult;
}


unsigned long PCI_RestoreECC(HANDLE hSessionHandle, unsigned long bFlagSign,
	const unsigned char *pbCipherValue, unsigned long ulCipherLen)
{
	unsigned long	ulResult = 0;
	unsigned long	ulTmpLen = 0;

	SGD_UINT32 ulSM2Bits = 256;

	unsigned long ulKeyIndex = bFlagSign ? (PCI_MAIN_KEY_ECC_SIGN):(PCI_MAIN_KEY_ECC_EX);

	if ( NULL == pbCipherValue)
	{
		return PCI_PARAM_ERR;
	}
	if( ulCipherLen != ulSM2Bits / 8 * 2 * 3)
	{
		return PCI_PARAM_ERR;
	}

	ulResult = SWCSM_RestoreImportECCKey(hSessionHandle, PCI_MAIN_KEY_ECC_SIGN,
		ulSM2Bits,pbCipherValue,ulCipherLen/2);
	if (ulResult)
	{
		return ulResult;
	}

	ulResult = SWCSM_RestoreImportECCKey(hSessionHandle, PCI_MAIN_KEY_ECC_EX,
		ulSM2Bits,pbCipherValue + ulCipherLen/2,ulCipherLen/2);
	if (ulResult)
	{
		return ulResult;
	}

	return ulResult;
}

unsigned long	PCI_RestoreFinal(HANDLE hSessionHandle)
{
	unsigned long	ulResult = 0;

	ulResult = SWCSM_RestoreFinal(hSessionHandle);

	if (0 != ulResult)
	{
		goto err;
	}

err:

	return ulResult;
}


unsigned long PCI_ExportRootSM2Keys(HANDLE hSessionHandle, unsigned char *pbPubKeyX, unsigned long *pulPubKeyLenX, unsigned char *pbPubKeyY, unsigned long *pulPubKeyLenY)
{
	unsigned long	ulResult = 0;

	ECCrefPublicKey pubSign = {0};

	ulResult = SDF_ExportSignPublicKey_ECC(hSessionHandle, PCI_MAIN_KEY_ECC, &pubSign);

	if (0 != ulResult)
	{
		goto err;
	}

	if (NULL == pbPubKeyX || NULL == pbPubKeyY)
	{
		*pulPubKeyLenX = ECCref_MAX_LEN;
		*pulPubKeyLenY = ECCref_MAX_LEN;
	}
	else if (*pulPubKeyLenX < ECCref_MAX_LEN || *pulPubKeyLenY < ECCref_MAX_LEN)
	{
		ulResult = OPE_ERR_NOT_ENOUGH_MEMORY;
	}
	else
	{
		*pulPubKeyLenX = ECCref_MAX_LEN;
		*pulPubKeyLenY = ECCref_MAX_LEN;

		memcpy(pbPubKeyX,pubSign.x, ECCref_MAX_LEN);
		memcpy(pbPubKeyY,pubSign.y, ECCref_MAX_LEN);
	}

err:

	return ulResult;
}
