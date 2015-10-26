
#include "com_java_common_CommonAPI.h"
#include "stdlib.h"
#include "sm2.h"
#include "string.h"
#include "x509.h"
#include "sm3.h"
#include "pci_func_def.h"
#include "o_all_type_def.h"
#include "openssl_func_def.h"
#include "FILE_LOG.h"
#include "modp_b64.h"
#include "o_all_func_def.h"

#define LCD_LEN 16 //LCD显示8个汉字,16字节
#define LCD_BLANK "\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20"

HANDLE hHandlePCI = 0;
HANDLE hHandleSession = 0;

unsigned long ulUserID[4] = {0};

unsigned long ulRet = 0;
unsigned long ulRetry = 0;

#define JNI_RELEASE_FLAG 1


jint Java_com_java_common_CommonAPI_PCIOpen
	(JNIEnv * env, jclass classObj)
{
	// 先关闭PCI卡
	if (NULL == hHandlePCI || NULL == hHandleSession)
	{

	}
	else
	{
		PCI_Close(hHandlePCI, hHandleSession);
		hHandlePCI = NULL;
		hHandleSession = NULL;
	}
	// 打开PCI卡
	ulRet = PCI_Open(&hHandlePCI, &hHandleSession);

err:

	return ulRet;
}

jint  Java_com_java_common_CommonAPI_PCIClose
	(JNIEnv * env, jclass classObj)
{
	// 未打开PCI卡
	if (NULL == hHandlePCI || NULL == hHandleSession)
	{
		ulRet = OPE_ERR_OK;
		goto err;
	}

	// 关闭PCI卡
	ulRet = PCI_Close(hHandlePCI, hHandleSession);
	if(0 == ulRet)
	{
		// 置0
		hHandlePCI = NULL;
		hHandleSession = NULL;
		ulRet = OPE_ERR_OK;
	}

err:

	return ulRet;
}



jint  Java_com_java_common_CommonAPI_PCILogin
	(JNIEnv *env, jclass classObj, jbyteArray byteArrayPIN, jint ulPINLen)
{
	jbyte* pbPin = (*env)->GetByteArrayElements(env, byteArrayPIN, JNI_FALSE);

	unsigned char szPIN[BUFFER_LEN_1K] = {0}; // 必须以0结束
	// 检测打开状态
	if (NULL == hHandlePCI || NULL == hHandleSession)
	{
		ulRet = OPE_ERR_PCI_NOT_INIT;
		goto err;
	}

	if (ulPINLen > BUFFER_LEN_1K)
	{
		ulRet =  OPE_ERR_INVALID_PARAM;
		goto err;
	}

	memcpy(szPIN,pbPin, ulPINLen);

	ulRet = PCI_ICLogin(hHandleSession,szPIN, ulPINLen,&(ulUserID[0]),&ulRetry);

err:
	// jni release
	if(JNI_RELEASE_FLAG)
	{
		(*env)->ReleaseByteArrayElements(env, byteArrayPIN, pbPin, JNI_FALSE);
	}

	return ulRet;
}

jint Java_com_java_common_CommonAPI_PCILogout
	(JNIEnv *env, jclass classObj, jint ulUserID)
{
	return PCI_ICLogout(hHandleSession, 2/*所有用户*/);
}

jint  Java_com_java_common_CommonAPI_PCICheckExistRootSM2Keys
	(JNIEnv * env, jclass classObj)
{
	// 检测打开状态
	if (NULL == hHandlePCI || NULL == hHandleSession)
	{
		ulRet = OPE_ERR_PCI_NOT_INIT;
		goto err;
	}

	ulRet = PCI_CheckExistRootSM2Keys(hHandleSession);

err:

	return ulRet;
}

jint  Java_com_java_common_CommonAPI_PCICheckNotExistRootSM2Keys
	(JNIEnv * env, jclass classObj)
{
	// 检测打开状态
	if (NULL == hHandlePCI || NULL == hHandleSession)
	{
		ulRet = OPE_ERR_PCI_NOT_INIT;
		goto err;
	}

	ulRet = PCI_CheckNotExistRootSM2Keys(hHandleSession);

err:

	return ulRet;
}


jint Java_com_java_common_CommonAPI_PCIGenRootSM2Keys
	(JNIEnv * env, jclass classObj)
{
	// 检测打开状态
	if (NULL == hHandlePCI || NULL == hHandleSession)
	{
		ulRet = OPE_ERR_PCI_NOT_INIT;
		goto err;
	}

	ulRet = PCI_GenRootSM2Keys(hHandleSession,NULL,NULL);

err:

	return ulRet;
}

jint Java_com_java_common_CommonAPI_PCIRestoreRootSM2Keys
	(JNIEnv * env, jclass classObj,jbyteArray byteArrayRootSM2Keys, jint ulKeysRootSM2Len)
{
	jbyte* pbKeys = (*env)->GetByteArrayElements(env, byteArrayRootSM2Keys, JNI_FALSE);

	// 检测打开状态
	if (NULL == hHandlePCI || NULL == hHandleSession)
	{
		ulRet = OPE_ERR_PCI_NOT_INIT;
		goto err;
	}

	ulRet = PCI_RestoreECC(hHandleSession,1,(unsigned char *)pbKeys,ulKeysRootSM2Len);

err:
	// jni release
	if(JNI_RELEASE_FLAG)
	{
		(*env)->ReleaseByteArrayElements(env, byteArrayRootSM2Keys, pbKeys, JNI_FALSE);
	}

	return ulRet;
}

jbyteArray Java_com_java_common_CommonAPI_PCIGenExportSM2Keys
	(JNIEnv * env, jclass classObj)
{
	unsigned long ulKeysLen = BUFFER_LEN_1K;
	unsigned char pbKeys[BUFFER_LEN_1K];

	// 检测打开状态
	if (NULL == hHandlePCI || NULL == hHandleSession)
	{
		ulRet = OPE_ERR_PCI_NOT_INIT;
		goto err;
	}

	ulRet = PCI_GenSM2Keys(hHandleSession, pbKeys, &ulKeysLen);

err:

	if(ulRet)
	{
		return NULL;
	}
	else
	{
		jbyteArray byteArrayRet;

		byteArrayRet = (*env)->NewByteArray(env,pbKeys);

		(*env)->SetByteArrayRegion(env,byteArrayRet,0,ulKeysLen,pbKeys);

		return byteArrayRet;
	}

}

jbyteArray Java_com_java_common_CommonAPI_PCIGenExportSM2EnvelopedKey
	(JNIEnv * env, jclass classObj, jbyteArray byteArrayEPK)
{
	unsigned long data_len = BUFFER_LEN_1K * 4;
	unsigned char data_value[BUFFER_LEN_1K * 4] = {0};

	jbyte * pbEPK = (*env)->GetByteArrayElements(env, byteArrayEPK, JNI_FALSE);
	jint iEPKLen = (*env)->GetArrayLength(env,byteArrayEPK);

	// 检测打开状态
	if (NULL == hHandlePCI || NULL == hHandleSession)
	{
		ulRet = OPE_ERR_PCI_NOT_INIT;
		goto err;
	}

	if (iEPKLen != 2*SM2_BYTES_LEN)
	{
		ulRet = OPE_ERR_INVALID_PARAM;
		goto err;
	}

	data_len = 2 * sizeof(OPST_SKF_ENVELOPEDKEYBLOB);

	ulRet = PCI_GenExportSM2EnvelopedKey(hHandleSession,
		(unsigned char *)pbEPK,
		(unsigned char *)pbEPK+SM2_BYTES_LEN,
		data_value,data_value + sizeof(OPST_SKF_ENVELOPEDKEYBLOB));

err:
	// jni release
	if(JNI_RELEASE_FLAG)
	{
		(*env)->ReleaseByteArrayElements(env, byteArrayEPK, pbEPK, JNI_FALSE);
	}

	if(ulRet)
	{
		return NULL;
	}
	else
	{
		jbyteArray byteArrayRet;

		byteArrayRet = (*env)->NewByteArray(env,data_len);

		(*env)->SetByteArrayRegion(env,byteArrayRet,0,data_len,data_value);

		return byteArrayRet;
	}
}

jbyteArray Java_com_java_common_CommonAPI_PCIRestoreExportSM2EnvelopedKey
	(JNIEnv * env, jclass classObj, jbyteArray byteArrayEPK, jbyteArray byteArrayIPKEnvlopedKeyBlob)
{
	unsigned long data_len = BUFFER_LEN_1K * 4;
	unsigned char data_value[BUFFER_LEN_1K * 4] = {0};

	jbyte * pbEPK = (*env)->GetByteArrayElements(env, byteArrayEPK, JNI_FALSE);
	jint iEPKLen = (*env)->GetArrayLength(env,byteArrayEPK);

	jbyte * pbIPKEnvlopedKeyBlob = (*env)->GetByteArrayElements(env, byteArrayIPKEnvlopedKeyBlob, JNI_FALSE);
	jint iIPKEnvlopedKeyBlobLen = (*env)->GetArrayLength(env,byteArrayIPKEnvlopedKeyBlob);

	// 检测打开状态
	if (NULL == hHandlePCI || NULL == hHandleSession)
	{
		ulRet = OPE_ERR_PCI_NOT_INIT;
		goto err;
	}

	if (iEPKLen != 2*SM2_BYTES_LEN || iIPKEnvlopedKeyBlobLen != sizeof(OPST_SKF_ENVELOPEDKEYBLOB))
	{
		ulRet = OPE_ERR_INVALID_PARAM;
		goto err;
	}

	data_len = sizeof(OPST_SKF_ENVELOPEDKEYBLOB);

	ulRet = PCI_RestoreExportSM2EnvelopedKey(hHandleSession,
		(unsigned char *)pbEPK,
		(unsigned char *)pbEPK+SM2_BYTES_LEN,
		pbIPKEnvlopedKeyBlob,data_value);

err:
	// jni release
	if(JNI_RELEASE_FLAG)
	{
		(*env)->ReleaseByteArrayElements(env, byteArrayIPKEnvlopedKeyBlob, pbIPKEnvlopedKeyBlob, JNI_FALSE);
		(*env)->ReleaseByteArrayElements(env, byteArrayEPK, pbEPK, JNI_FALSE);
	}

	if(ulRet)
	{
		return NULL;
	}
	else
	{
		jbyteArray byteArrayRet;

		FILE_LOG_HEX(file_log_name,data_value,data_len);

		byteArrayRet = (*env)->NewByteArray(env,data_len);

		(*env)->SetByteArrayRegion(env,byteArrayRet,0,data_len,data_value);

		return byteArrayRet;
	}
}


jbyteArray Java_com_java_common_CommonAPI_PCIBackupRootSM2Keys
	(JNIEnv * env, jclass classObj)
{
	unsigned long ulKeys = BUFFER_LEN_1K;
	unsigned char pbKeys[BUFFER_LEN_1K];


	// 检测打开状态
	if (NULL == hHandlePCI || NULL == hHandleSession)
	{
		ulRet = OPE_ERR_PCI_NOT_INIT;
		goto err;
	}

	ulRet = PCI_BackupECC(hHandleSession, 1, pbKeys, &ulKeys);

err:

	if(ulRet)
	{
		return NULL;
	}
	else
	{
		jbyteArray byteArrayRet;

		byteArrayRet = (*env)->NewByteArray(env,ulKeys);

		(*env)->SetByteArrayRegion(env,byteArrayRet,0,ulKeys,pbKeys);

		return byteArrayRet;
	}
}


jint Java_com_java_common_CommonAPI_GetLassErrorNumber(JNIEnv * env, jclass classObj)
{
	return (jint)ulRet;
}

jint Java_com_java_common_CommonAPI_GetPasswordRetry(JNIEnv * env, jclass classObj)
{
	return ulRetry;
}


jbyteArray Java_com_java_common_CommonAPI_OpenSSLSM2GenCSRWithPubkey(JNIEnv * env, jclass classObj, jobject objUserInfo ,jbyteArray byteArraySM2Keys)
{
	OPST_USERINFO userInfo;

	unsigned long ulCSRLen = BUFFER_LEN_1K;
	unsigned char pbCSR[BUFFER_LEN_1K]  = {0};

	unsigned long data_len_x = SM2_BYTES_LEN;
	unsigned char data_value_x[SM2_BYTES_LEN];

	unsigned long data_len_y = SM2_BYTES_LEN;
	unsigned char data_value_y[SM2_BYTES_LEN];

	jclass cls = (*env)->GetObjectClass(env,objUserInfo);  

	jfieldID ID_countryName = (*env)->GetFieldID(env,cls, "_countryName", "Ljava/lang/String;");  
	jstring str_countryName = (jstring)((*env)->GetObjectField(env,objUserInfo, ID_countryName));  
	jchar * c_countryName  = (jchar *)(*env)->GetStringUTFChars(env, str_countryName, NULL);
	int len_countryName =  (*env)->GetStringUTFLength(env,str_countryName);

	jfieldID ID_stateOrProvinceName = (*env)->GetFieldID(env,cls, "_stateOrProvinceName", "Ljava/lang/String;");  
	jstring str_stateOrProvinceName = (jstring)((*env)->GetObjectField(env,objUserInfo, ID_stateOrProvinceName));  
	jchar * c_stateOrProvinceName  = (jchar *)(*env)->GetStringUTFChars(env, str_stateOrProvinceName, NULL);
	int len_stateOrProvinceName =  (*env)->GetStringUTFLength(env,str_stateOrProvinceName);

	jfieldID ID_localityName = (*env)->GetFieldID(env,cls, "_localityName", "Ljava/lang/String;");  
	jstring str_localityName = (jstring)((*env)->GetObjectField(env,objUserInfo, ID_localityName));  
	jchar * c_localityName  = (jchar *)(*env)->GetStringUTFChars(env, str_localityName, NULL);
	int len_localityName =  (*env)->GetStringUTFLength(env,str_localityName);

	jfieldID ID_organizationName = (*env)->GetFieldID(env,cls, "_organizationName", "Ljava/lang/String;");  
	jstring str_organizationName = (jstring)((*env)->GetObjectField(env,objUserInfo, ID_organizationName));  
	jchar * c_organizationName  = (jchar *)(*env)->GetStringUTFChars(env, str_organizationName, NULL);
	int len_organizationName =  (*env)->GetStringUTFLength(env,str_organizationName);

	jfieldID ID_organizationalUnitName = (*env)->GetFieldID(env,cls, "_organizationalUnitName", "Ljava/lang/String;");  
	jstring str_organizationalUnitName = (jstring)((*env)->GetObjectField(env,objUserInfo, ID_organizationalUnitName));  
	jchar * c_organizationalUnitName  = (jchar *)(*env)->GetStringUTFChars(env, str_organizationalUnitName, NULL);
	int len_organizationalUnitName =  (*env)->GetStringUTFLength(env,str_organizationalUnitName);

	jfieldID ID_commonName = (*env)->GetFieldID(env,cls, "_commonName", "Ljava/lang/String;");  
	jstring str_commonName = (jstring)((*env)->GetObjectField(env,objUserInfo, ID_commonName));  
	jchar * c_commonName  = (jchar *)(*env)->GetStringUTFChars(env, str_commonName, NULL);
	int len_commonName =  (*env)->GetStringUTFLength(env,str_commonName);

	jfieldID ID_challengePassword = (*env)->GetFieldID(env,cls, "_challengePassword", "Ljava/lang/String;");  
	jstring str_challengePassword = (jstring)((*env)->GetObjectField(env,objUserInfo, ID_challengePassword));  
	jchar * c_challengePassword  = (jchar *)(*env)->GetStringUTFChars(env, str_challengePassword, NULL);
	int len_challengePassword =  (*env)->GetStringUTFLength(env,str_challengePassword);

	jfieldID ID_unstructuredName = (*env)->GetFieldID(env,cls, "_unstructuredName", "Ljava/lang/String;");  
	jstring str_unstructuredName = (jstring)((*env)->GetObjectField(env,objUserInfo, ID_unstructuredName));  
	jchar * c_unstructuredName  = (jchar *)(*env)->GetStringUTFChars(env, str_unstructuredName, NULL);
	int len_unstructuredName =  (*env)->GetStringUTFLength(env,str_unstructuredName);

	jfieldID ID_idCardNumber = (*env)->GetFieldID(env,cls, "_idCardNumber", "Ljava/lang/String;");  
	jstring str_idCardNumber = (jstring)((*env)->GetObjectField(env,objUserInfo, ID_idCardNumber));  
	jchar * c_idCardNumber  = (jchar *)(*env)->GetStringUTFChars(env, str_idCardNumber, NULL);
	int len_idCardNumber =  (*env)->GetStringUTFLength(env,str_idCardNumber);

	jfieldID ID_emailAddress = (*env)->GetFieldID(env,cls, "_emailAddress", "Ljava/lang/String;");  
	jstring str_emailAddress = (jstring)((*env)->GetObjectField(env,objUserInfo, ID_emailAddress));  
	jchar * c_emailAddress  = (jchar *)(*env)->GetStringUTFChars(env, str_emailAddress, NULL);
	int len_emailAddress =  (*env)->GetStringUTFLength(env,str_emailAddress);

	jbyte * pbSM2Keys = NULL;

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "hHandlePCI");
	FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, hHandlePCI);

	// 检测打开状态
	if (NULL == hHandlePCI || NULL == hHandleSession)
	{
		ulRet = OPE_ERR_PCI_NOT_INIT;
		goto err;
	}

	if (byteArraySM2Keys)
	{
		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "byteArraySM2Keys");
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, byteArraySM2Keys);

		pbSM2Keys = (*env)->GetByteArrayElements(env, byteArraySM2Keys, JNI_FALSE);

		memcpy(data_value_y,pbSM2Keys + 4 + SM2_BYTES_LEN,SM2_BYTES_LEN);
		memcpy(data_value_x,pbSM2Keys + 4, SM2_BYTES_LEN);

		if(JNI_RELEASE_FLAG)
		{
			(*env)->ReleaseByteArrayElements(env, byteArraySM2Keys, pbSM2Keys, JNI_FALSE);
		}
	}
	else
	{
		ulRet = PCI_ExportRootSM2Keys(hHandleSession,data_value_x,&data_len_x,data_value_y,&data_len_y);

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "ulRet");
		FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, ulRet);

		if (ulRet)
		{
			goto err;
		}
	}

	userInfo.ulLenC = (len_countryName)*1;
	userInfo.ulLenST = (len_stateOrProvinceName)*1;
	userInfo.ulLenL = (len_localityName)*1;
	userInfo.ulLenO = (len_organizationName)*1;
	userInfo.ulLenOU = (len_organizationalUnitName)*1;
	userInfo.ulLenCN = (len_commonName)*1;
	userInfo.ulLenEA = (len_emailAddress)*1;
	userInfo.ulLenCP = (len_challengePassword)*1;
	userInfo.ulLenUN = (len_unstructuredName)*1;

	memcpy(userInfo.countryName, c_countryName, userInfo.ulLenC);
	memcpy( userInfo.stateOrProvinceName ,c_stateOrProvinceName, userInfo.ulLenST);
	memcpy( userInfo.localityName,c_localityName, userInfo.ulLenL);
	memcpy( userInfo.organizationName, c_organizationName,userInfo.ulLenO);
	memcpy(userInfo.organizationalUnitName,c_organizationalUnitName, userInfo.ulLenOU);
	memcpy( userInfo.commonName,c_commonName,userInfo.ulLenCN);
	memcpy( userInfo.emailAddress,c_emailAddress,userInfo.ulLenEA);
	memcpy( userInfo.challengePassword,c_challengePassword, userInfo.ulLenCP);
	memcpy( userInfo.unstructuredName,c_unstructuredName, userInfo.ulLenUN);

	OpenSSL_Initialize();



	ulRet = OpenSSL_SM2GenCSRWithPubkey(&userInfo, data_value_x, data_len_x,data_value_y,data_len_y,pbCSR,&ulCSRLen);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "ulRet");
	FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, ulRet);

	OpenSSL_Finalize();

err:

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "00");

	// jni release
	if(JNI_RELEASE_FLAG)
	{
		/*
		if (c_emailAddress)
		{
			(*env)->ReleaseStringUTFChars(env, str_emailAddress, c_emailAddress, JNI_FALSE);
		}
		
		if (c_idCardNumber)
		{
		(*env)->ReleaseStringUTFChars(env, str_idCardNumber, c_idCardNumber, JNI_FALSE);
		}

		if (c_unstructuredName)
		{
		(*env)->ReleaseStringUTFChars(env, str_unstructuredName, c_unstructuredName, JNI_FALSE);
		}

		if (c_challengePassword)
		{
		(*env)->ReleaseStringUTFChars(env, str_challengePassword, c_challengePassword, JNI_FALSE);
		}

		if (c_commonName)
		{
		(*env)->ReleaseStringUTFChars(env, str_commonName, c_commonName, JNI_FALSE);
		}

		if (c_organizationName)
		{
		(*env)->ReleaseStringUTFChars(env, str_organizationName, c_organizationName, JNI_FALSE);
		}

		if (c_organizationalUnitName)
		{
		(*env)->ReleaseStringUTFChars(env, str_organizationalUnitName, c_organizationalUnitName, JNI_FALSE);
		}

		if (c_localityName)
		{
		(*env)->ReleaseStringUTFChars(env, str_localityName, c_localityName, JNI_FALSE);
		}

		if (c_stateOrProvinceName)
		{
		(*env)->ReleaseStringUTFChars(env, str_stateOrProvinceName, c_stateOrProvinceName, JNI_FALSE);
		}

		if (c_countryName)
		{
		(*env)->ReleaseStringUTFChars(env, str_countryName, c_countryName, JNI_FALSE);
		}*/
	}

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "00");

	if(ulRet)
	{
		return NULL;
	}
	else
	{
		jbyteArray byteArrayRet;

		byteArrayRet = (*env)->NewByteArray(env,ulCSRLen);

		(*env)->SetByteArrayRegion(env,byteArrayRet,0,ulCSRLen,pbCSR);

		return byteArrayRet;
	}
}


jbyteArray Java_com_java_common_CommonAPI_OpenSSLSM2GenRootCert(JNIEnv * env, jclass classObj, jbyteArray byteArrayCSR, jbyteArray byteArraySN, jint ulSNLen, jint ulDATE)
{
	unsigned long ulX509CertLen = BUFFER_LEN_1K * 4;
	unsigned char pbX509Cert[BUFFER_LEN_1K * 4] = {0};

	jbyte * pbCSR = (*env)->GetByteArrayElements(env, byteArrayCSR, JNI_FALSE);
	jbyte * pbSN = (*env)->GetByteArrayElements(env, byteArraySN, JNI_FALSE);
	jint ulCSRLen = (*env)->GetArrayLength(env,byteArrayCSR);

	OpenSSL_Initialize();

	ulRet = OpenSSL_SM2GenRootCert((unsigned char *)pbCSR, ulCSRLen,pbSN, ulSNLen,0,ulDATE,pbX509Cert,&ulX509CertLen);

	OpenSSL_Finalize();

err:
	// jni release
	if(JNI_RELEASE_FLAG)
	{
		(*env)->ReleaseByteArrayElements(env, byteArrayCSR, pbCSR, JNI_FALSE);
		(*env)->ReleaseByteArrayElements(env, byteArraySN, pbSN, JNI_FALSE);
	}

	if(ulRet)
	{
		return NULL;
	}
	else
	{
		jbyteArray byteArrayRet;
		byteArrayRet = (*env)->NewByteArray(env,ulX509CertLen);

		(*env)->SetByteArrayRegion(env,byteArrayRet,0,ulX509CertLen,pbX509Cert);

		return byteArrayRet;
	}
}


jbyteArray Java_com_java_common_CommonAPI_OpenSSLSM2GenCert(JNIEnv * env, jclass classObj,
	jbyteArray byteArrayRootCert, jbyteArray byteArrayCSR, 
	jbyteArray byteArraySN, jint ulSNLen, 
	jint ulDATE, jint ulTypeSignEncrypt)
{
	int ulCSRLen = 0;
	unsigned long ulRootCertLen = 0;

	unsigned long ulX509CertLen = BUFFER_LEN_1K * 4;
	unsigned char pbX509Cert[BUFFER_LEN_1K * 4] = {0};

	jbyte * pbCSR = (*env)->GetByteArrayElements(env, byteArrayCSR, JNI_FALSE);
	jbyte * pbSN = (*env)->GetByteArrayElements(env, byteArraySN, JNI_FALSE);
	jbyte * pbRootCert = (*env)->GetByteArrayElements(env, byteArrayRootCert, JNI_FALSE);

	ulCSRLen = (*env)->GetArrayLength(env,byteArrayCSR);
	ulRootCertLen = (*env)->GetArrayLength(env,byteArrayRootCert);

	OpenSSL_Initialize();

	ulRet = OpenSSL_SM2GenCert((unsigned char *)pbCSR, ulCSRLen,
		(unsigned char *)pbRootCert,ulRootCertLen,pbSN, ulSNLen,0,ulDATE,ulTypeSignEncrypt,pbX509Cert,&ulX509CertLen);

	OpenSSL_Finalize();

err:
	// jni release
	if(JNI_RELEASE_FLAG)
	{
		(*env)->ReleaseByteArrayElements(env, byteArrayCSR, pbCSR, JNI_FALSE);
		(*env)->ReleaseByteArrayElements(env, byteArrayRootCert, pbRootCert, JNI_FALSE);
		(*env)->ReleaseByteArrayElements(env, byteArraySN, pbSN, JNI_FALSE);
	}

	if(ulRet)
	{
		return NULL;
	}
	else
	{
		jbyteArray byteArrayRet;
		byteArrayRet = (*env)->NewByteArray(env,ulX509CertLen);

		(*env)->SetByteArrayRegion(env,byteArrayRet,0,ulX509CertLen,pbX509Cert);

		return byteArrayRet;
	}
}

jbyteArray Java_com_java_common_CommonAPI_OpenSSLSM2GenCertEX(
	JNIEnv * env, jclass classObj,
	jbyteArray byteArrayRootCert,
	jbyteArray byteArrayPublicKey, jbyteArray byteArrayCSR, 
	jbyteArray byteArraySN, jint ulSNLen, 
	jint ulDATE, jint ulTypeSignEncrypt)
{
	int ulCSRLen = 0;
	unsigned long ulRootCertLen = 0;
	unsigned long data_len_publickey = 0;

	unsigned long ulX509CertLen = BUFFER_LEN_1K * 4;
	unsigned char pbX509Cert[BUFFER_LEN_1K * 4] = {0};

	jbyte * pbCSR = (*env)->GetByteArrayElements(env, byteArrayCSR, JNI_FALSE);
	jbyte * pbSN = (*env)->GetByteArrayElements(env, byteArraySN, JNI_FALSE);
	jbyte * pbPublicKey = (*env)->GetByteArrayElements(env, byteArrayPublicKey, JNI_FALSE);
	jbyte * pbRootCert = (*env)->GetByteArrayElements(env, byteArrayRootCert, JNI_FALSE);

	ulCSRLen = (*env)->GetArrayLength(env,byteArrayCSR);
	ulRootCertLen = (*env)->GetArrayLength(env,byteArrayRootCert);
	data_len_publickey = (*env)->GetArrayLength(env,byteArrayPublicKey);

	if (2 * SM2_BYTES_LEN != data_len_publickey)
	{
		ulRet = OPE_ERR_INVALID_PARAM;
		goto err;
	}

	OpenSSL_Initialize();

	ulRet = OpenSSL_SM2GenCertEX((unsigned char *)pbCSR, ulCSRLen,
		(unsigned char *)pbPublicKey,SM2_BYTES_LEN,
		(unsigned char *)pbPublicKey + SM2_BYTES_LEN, SM2_BYTES_LEN,
		(unsigned char *)pbRootCert,ulRootCertLen, pbSN, ulSNLen,0,ulDATE,1,pbX509Cert,&ulX509CertLen);

	OpenSSL_Finalize();

err:

	// jni release
	if(JNI_RELEASE_FLAG)
	{
		(*env)->ReleaseByteArrayElements(env, byteArrayCSR, pbCSR, JNI_FALSE);
		(*env)->ReleaseByteArrayElements(env, byteArrayRootCert, pbRootCert, JNI_FALSE);
		(*env)->ReleaseByteArrayElements(env, byteArrayPublicKey, pbPublicKey, JNI_FALSE);
		(*env)->ReleaseByteArrayElements(env, byteArraySN, pbSN, JNI_FALSE);
	}

	if(ulRet)
	{
		return NULL;
	}
	else
	{
		jbyteArray byteArrayRet;

		byteArrayRet = (*env)->NewByteArray(env,ulX509CertLen);

		(*env)->SetByteArrayRegion(env,byteArrayRet,0,ulX509CertLen,pbX509Cert);

		return byteArrayRet;
	}
}



jbyteArray Java_com_java_common_CommonAPI_OPFSM2SignCert(JNIEnv * env, jclass classObj, jbyteArray byteArrayX509Cert)
{
	unsigned long ulX509CertSignedLen = BUFFER_LEN_1K * 4;
	unsigned char pbX509CertSigned[BUFFER_LEN_1K * 4] = {0};

	jbyte * pbX509Cert = (*env)->GetByteArrayElements(env, byteArrayX509Cert, JNI_FALSE);
	jint ulX509CertLen = (*env)->GetArrayLength(env,byteArrayX509Cert);

	if (NULL == hHandlePCI || NULL == hHandleSession)
	{
		ulRet = OPE_ERR_PCI_NOT_INIT;
		goto err;
	}

	OpenSSL_Initialize();

	ulRet = OPF_SM2SignCert(hHandleSession, (unsigned char *)pbX509Cert, ulX509CertLen,0 ,pbX509CertSigned,&ulX509CertSignedLen);

	OpenSSL_Finalize();

err:
	// jni release
	if(JNI_RELEASE_FLAG)
	{
		(*env)->ReleaseByteArrayElements(env, byteArrayX509Cert, pbX509Cert, JNI_FALSE);
	}

	if(ulRet)
	{
		return NULL;
	}
	else
	{
		jbyteArray byteArrayRet;

		byteArrayRet = (*env)->NewByteArray(env,ulX509CertSignedLen);

		(*env)->SetByteArrayRegion(env,byteArrayRet,0,ulX509CertSignedLen,pbX509CertSigned);

		return byteArrayRet;
	}
}

jbyteArray Java_com_java_common_CommonAPI_Base64Encode(JNIEnv * env, jclass classObj,jbyteArray byteArrayIN, jint ulINLen)
{
	jbyteArray byteArrayRet;

	unsigned long ulOUTLen = BUFFER_LEN_1K * 4;
	unsigned char pbOUT[BUFFER_LEN_1K * 4] = {0};

	jbyte * pbIN = (*env)->GetByteArrayElements(env, byteArrayIN, JNI_FALSE);

	ulOUTLen = modp_b64_encode(pbOUT,pbIN,ulINLen);

	byteArrayRet = (*env)->NewByteArray(env,ulOUTLen);

	(*env)->SetByteArrayRegion(env,byteArrayRet,0,ulOUTLen,pbOUT);

	if(JNI_RELEASE_FLAG)
	{
		(*env)->ReleaseByteArrayElements(env, byteArrayIN, pbIN, JNI_FALSE);
	}

	return byteArrayRet;
}

jbyteArray Java_com_java_common_CommonAPI_Base64Decode(JNIEnv * env, jclass classObj,jbyteArray byteArrayIN, jint ulINLen)
{
	jbyteArray byteArrayRet;

	unsigned long ulOUTLen = BUFFER_LEN_1K * 4;
	unsigned char pbOUT[BUFFER_LEN_1K * 4] = {0};

	jbyte * pbIN = (*env)->GetByteArrayElements(env, byteArrayIN, JNI_FALSE);

	ulOUTLen = modp_b64_decode(pbOUT,pbIN,ulINLen);

	byteArrayRet = (*env)->NewByteArray(env,ulOUTLen);

	(*env)->SetByteArrayRegion(env,byteArrayRet,0,ulOUTLen,pbOUT);

	if(JNI_RELEASE_FLAG)
	{
		(*env)->ReleaseByteArrayElements(env, byteArrayIN, pbIN, JNI_FALSE);
	}

	return byteArrayRet;
}

JNIEXPORT jbyteArray Java_com_java_common_CommonAPI_OpenSSLSM2GenCRL(JNIEnv *env, jobject classObj,jobjectArray objArray, jbyteArray byteArrayX509Cert, jint ulX509CertLen)
{
	int i;
	jobject obj;        
	int len;
	jclass cls;
	jfieldID fid_sn;// 序列号
	jfieldID fid_snlen;// 序列号
	jfieldID fid_reason_code;// 吊销缘由
	jfieldID fid_dt; // 吊销时间
	unsigned long data_len = BUFFER_LEN_1K * 4;
	unsigned char data_value[BUFFER_LEN_1K * 4] = {0};
	OPST_CRL * crl = NULL;

	jbyte * pbX509Cert = (*env)->GetByteArrayElements(env, byteArrayX509Cert, JNI_FALSE);


	len = (*env)->GetArrayLength(env, objArray);

	cls = (*env)->FindClass(env, "com/java/model/UserCert");   

	fid_sn = (*env)->GetFieldID(env, cls, "sn", "I"); 
	fid_snlen = (*env)->GetFieldID(env, cls, "snlen", "I");

	fid_reason_code = (*env)->GetFieldID(env, cls, "reason_code", "I"); 

	fid_dt = (*env)->GetFieldID(env, cls, "dt", "I"); 

	crl = (OPST_CRL *)malloc(sizeof(OPST_CRL) * len);

	for ( i = 0; i<len; i++)
	{
		obj = (*env)->GetObjectArrayElement(env, objArray, i);
		crl[i].sn = (jbyteArray)(*env)->GetObjectField(env, obj, fid_sn);

		crl[i].snlen = (*env)->GetIntField(env, obj, fid_snlen);

		crl[i].reason_code = (*env)->GetIntField(env, obj, fid_reason_code);
		crl[i].dt = (*env)->GetIntField(env, obj, fid_dt);
	}

	ulRet = OpenSSL_SM2GenCRL(crl,len, (const unsigned char *)pbX509Cert,ulX509CertLen,data_value,&data_len);

err:

	if(JNI_RELEASE_FLAG)
	{
		(*env)->ReleaseByteArrayElements(env, byteArrayX509Cert, pbX509Cert, JNI_FALSE);
	}

	if (crl)
	{
		free(crl);
	}

	if(ulRet)
	{
		return NULL;
	}
	else
	{
		jbyteArray byteArrayRet = NULL;

		byteArrayRet = (*env)->NewByteArray(env,data_len);

		(*env)->SetByteArrayRegion(env,byteArrayRet,0,data_len,data_value);

		return byteArrayRet;
	}
}

jbyteArray Java_com_java_common_CommonAPI_OPFSM2SignCRL(JNIEnv * env, jclass classObj, jbyteArray byteArrayCRL,jbyteArray byteArrayX509Cert, jint ulX509CertLen)
{
	unsigned long ulCRLSignedLen = BUFFER_LEN_1K * 4;
	unsigned char pbCRLSigned[BUFFER_LEN_1K * 4] = {0};

	jbyte * pbCRL = (*env)->GetByteArrayElements(env, byteArrayCRL, JNI_FALSE);
	jint ulCRLLen = (*env)->GetArrayLength(env,byteArrayCRL);

	jbyte * pbX509Cert = (*env)->GetByteArrayElements(env, byteArrayX509Cert, JNI_FALSE);

	if (NULL == hHandlePCI || NULL == hHandleSession)
	{
		ulRet = OPE_ERR_PCI_NOT_INIT;
		goto err;
	}
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "hHandlePCI");
	FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, hHandlePCI);


	OpenSSL_Initialize();

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "pbX509Cert");
	FILE_LOG_HEX(file_log_name,(unsigned char *) pbX509Cert, ulX509CertLen);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "pbCRL");
	FILE_LOG_HEX(file_log_name,(unsigned char *) pbCRL, ulCRLLen);

	ulRet = OPF_SM2SignCRL(hHandleSession, (const unsigned char *)pbX509Cert, ulX509CertLen, (unsigned char *)pbCRL, ulCRLLen, 0, pbCRLSigned,&ulCRLSignedLen);

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "pbCRLSigned");
	FILE_LOG_HEX(file_log_name,(unsigned char *) pbCRLSigned, ulCRLSignedLen);

	OpenSSL_Finalize();

err:

	if(JNI_RELEASE_FLAG)
	{
		(*env)->ReleaseByteArrayElements(env, byteArrayCRL, pbCRL, JNI_FALSE);
		(*env)->ReleaseByteArrayElements(env, byteArrayX509Cert, pbX509Cert, JNI_FALSE);
	}

	if(ulRet)
	{
		return NULL;
	}
	else
	{
		jbyteArray byteArrayRet;

		byteArrayRet = (*env)->NewByteArray(env,ulCRLSignedLen);

		(*env)->SetByteArrayRegion(env,byteArrayRet,0,ulCRLSignedLen,pbCRLSigned);

		return byteArrayRet;
	}

}

// 备份根密钥
jint Java_com_java_common_CommonAPI_PCIBackupInit
	(JNIEnv * env, jclass classObj)
{
	if (NULL == hHandlePCI || NULL == hHandleSession)
	{
		ulRet = OPE_ERR_PCI_NOT_INIT;
		goto err;
	}
	else
	{
		ulRet = PCI_BackupInit(hHandleSession);
	}
err:

	return ulRet;
}

jint Java_com_java_common_CommonAPI_PCIBackupKeyComponent
	(JNIEnv * env, jclass classObj, jint ulNumber,jbyteArray pbPIN, jint ulPINLen)
{
	jbyte* pin = (*env)->GetByteArrayElements(env, pbPIN, JNI_FALSE);

	unsigned char szPIN[BUFFER_LEN_1K] = {0}; // 必须以0结束

	// 检测打开状态
	if (NULL == hHandlePCI || NULL == hHandleSession)
	{
		ulRet = OPE_ERR_PCI_NOT_INIT;
		goto err;
	}

	if (ulPINLen > BUFFER_LEN_1K)
	{
		ulRet = OPE_ERR_INVALID_PARAM;
		goto err;
	}

	memcpy(szPIN,pin, ulPINLen);

	ulRet = PCI_BackupKeyComponent(hHandleSession,ulNumber, szPIN,ulPINLen,&ulRetry);

err:

	return ulRet;

}
jint Java_com_java_common_CommonAPI_PCIBackupFinal
	(JNIEnv * env, jclass classObj)
{
	// 检测打开状态
	if (NULL == hHandlePCI || NULL == hHandleSession)
	{
		ulRet = OPE_ERR_PCI_NOT_INIT;
		goto err;
	}
	else
	{
		ulRet = PCI_BackupFinal(hHandleSession);
	}
err:

	return ulRet;
}

// 恢复根密钥 
jint Java_com_java_common_CommonAPI_PCIRestoreInit
	(JNIEnv * env, jclass classObj)
{
	// 检测打开状态
	if (NULL == hHandlePCI || NULL == hHandleSession)
	{
		ulRet = OPE_ERR_PCI_NOT_INIT;
		goto err;
	}
	else
	{
		ulRet = PCI_RestoreInit(hHandleSession);
	}

err:

	return ulRet;
}

jint Java_com_java_common_CommonAPI_PCIRestoreKeyComponent
	(JNIEnv * env, jclass classObj,jbyteArray pbPin, jint ulPINLen)
{
	jbyte* pin = (*env)->GetByteArrayElements(env, pbPin, JNI_FALSE);

	unsigned char szPIN[BUFFER_LEN_1K] = {0}; // 必须以0结束

	// 检测打开状态
	if (NULL == hHandlePCI || NULL == hHandleSession)
	{
		ulRet = OPE_ERR_PCI_NOT_INIT;
		goto err;
	}

	if (ulPINLen > BUFFER_LEN_1K)
	{
		ulRet = OPE_ERR_INVALID_PARAM;
		goto err;
	}

	memcpy(szPIN,pin, ulPINLen);

	ulRet = PCI_RestoreKeyComponent(hHandleSession, szPIN ,ulPINLen,&ulRetry);

err:

	return ulRet;
}

jint Java_com_java_common_CommonAPI_PCIRestoreFinal
	(JNIEnv * env, jclass classObj)
{
	// 检测打开状态
	if (NULL == hHandlePCI || NULL == hHandleSession)
	{
		ulRet = OPE_ERR_PCI_NOT_INIT;
		goto err;
	}
	else
	{
		ulRet =  PCI_RestoreFinal(hHandleSession);
	}

err:
	return ulRet;
}

jint Java_com_java_common_CommonAPI_OpenSSLVerifyValidCodeSign
	(JNIEnv * env, jobject objclass, 
	jbyteArray byteArrayValidCode, jint ulValidCodeLen, /*验证码*/
	jbyteArray byteArrayPublicKey, jint ulPublicKeyLen, /*公钥*/
	jbyteArray byteArraySig, jint ulSigLen				/*签名值*/
	)
{
	jint ret = -1;

	jbyte* pbValidCode = (*env)->GetByteArrayElements(env, byteArrayValidCode, JNI_FALSE);
	jbyte* pbPublicKey = (*env)->GetByteArrayElements(env, byteArrayPublicKey, JNI_FALSE);
	jbyte* pbSig = (*env)->GetByteArrayElements(env, byteArraySig, JNI_FALSE);
	
	unsigned char pbDigestValue[SM3_DIGEST_LEN] = {0};
	unsigned long ulDigestLen = SM3_DIGEST_LEN;

	unsigned char pbSignValue[BUFFER_LEN_1K];
	unsigned long ulSignLen = BUFFER_LEN_1K;

	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "pbValidCode");
	FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__, hHandlePCI);


	// base64转换
	ulSignLen = modp_b64_decode((char *)pbSignValue,(char *)pbSig,ulSigLen);

	ret = tcm_sch_hash(ulValidCodeLen,(unsigned char *)pbValidCode,pbDigestValue);

	if(0 != ret)
	{
		goto err;
	}

	OpenSSL_Initialize();

	ret = OpenSSL_SM2VerifyDigest(pbDigestValue,SM3_DIGEST_LEN,
		pbSignValue,ulSignLen,(unsigned char *)pbPublicKey,SM2_BYTES_LEN,(unsigned char *)pbPublicKey+SM2_BYTES_LEN,SM2_BYTES_LEN);

	if(0 != ret)
	{
		goto err;
	}

	OpenSSL_Finalize();
err:

	if(JNI_RELEASE_FLAG)
	{
		//(*env)->ReleaseByteArrayElements(env, pbValidCode, byteArrayValidCode,JNI_FALSE);
		//(*env)->ReleaseByteArrayElements(env, pbPublicKey,byteArrayPublicKey, JNI_FALSE);
		//(*env)->ReleaseByteArrayElements(env, pbSig,byteArraySig, JNI_FALSE);
	}

	return ret;
}
