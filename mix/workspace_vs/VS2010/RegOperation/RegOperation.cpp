#include "RegOperation.h"

CRegOperation * CRegOperation::_instance = 0;

CRegOperation* CRegOperation::Instance() 
{ 
	if (_instance == 0) 
	{
		_instance = new CRegOperation(); 
	}

	return _instance; 
}

CRegOperation::CRegOperation(void)
{
	m_pRootCert = 0;
	m_iRootCertLength = 0;

	m_pSelfCert = 0;
	m_iSelfCertLength = 0;

	m_pPrivateKey = 0;
	m_iPrivateKeyLength = 0;

	m_uHASH = 0; 
	m_uSymmetric = 0;
	m_uASymmetric = 0;
}

CRegOperation::~CRegOperation(void)
{
	if(NULL != m_pRootCert)
	{
		free(m_pRootCert);
	}
	if(NULL != m_pSelfCert)
	{
		free(m_pSelfCert);
	}
	if(NULL != m_pPrivateKey)
	{
		free(m_pPrivateKey);
	}
}

int CRegOperation::Installation()
{
	int iRet = 0;

	HKEY hKey;

	char *szValueNamePrivateKey = REG_VALUE_NAME_PrivateKey;
	char *szValueDataPrivateKey = REG_VALUE_DATA_PrivateKey;
	int cbLenPrivateKey = strlen(szValueDataPrivateKey);

	char *szValueNameRootCert = REG_VALUE_NAME_RootCert;
	char *szValueDataRootCert = REG_VALUE_DATA_RootCert;
	int cbLenRootCert = strlen(szValueDataRootCert);

	char *szValueNameSelfCert = REG_VALUE_NAME_SelfCert;
	char *szValueDataSelfCert = REG_VALUE_DATA_SelfCert;
	int cbLenSelfCert = strlen(szValueDataRootCert);

	char *szValueNameHASH = REG_VALUE_NAME_HASH;
	UINT uHASH = REG_VALUE_DATA_HASH;
	UINT *szValueDataHASH = &uHASH;

	char *szValueNameSymmetric = REG_VALUE_NAME_Symmetric;
	UINT uSymmetric = REG_VALUE_DATA_Symmetric;
	UINT *szValueDataSymmetric = &uSymmetric;

	char *szValueNameASymmetric = REG_VALUE_NAME_ASymmetric;
	UINT uASymmetric = REG_VALUE_DATA_ASymmetric;
	UINT *szValueDataASymmetric = &uASymmetric;

	if(ERROR_SUCCESS!=RegCreateKey(REG_ROOT_KEY,REG_SUB_KEY,&hKey))
	{
		printf("创建子键失败!\n");
		iRet = -1;
	}
	else
	{
		printf("创建子键成功!\n");
	}

	if(RegSetValueEx(hKey,szValueNamePrivateKey,0,REG_BINARY,(const unsigned char *)szValueDataPrivateKey,cbLenPrivateKey)==ERROR_SUCCESS)
	{
		printf("创建REG_BINARY键值成功!\n");
	}
	else
	{
		printf("创建REG_BINARY键值失败!\n");
		iRet = -1;
	}


	if(RegSetValueEx(hKey,szValueNameSelfCert,0,REG_BINARY,(const unsigned char *)szValueDataSelfCert,cbLenSelfCert)==ERROR_SUCCESS)
	{
		printf("创建REG_BINARY键值成功!\n");
	}
	else
	{
		printf("创建REG_BINARY键值失败!\n");
		iRet = -1;
	}

	if(RegSetValueEx(hKey,szValueNameRootCert,0,REG_BINARY,(const unsigned char *)szValueDataRootCert,cbLenRootCert)==ERROR_SUCCESS)
	{
		printf("创建REG_BINARY键值成功!\n");
	}
	else
	{
		printf("创建REG_BINARY键值失败!\n");
		iRet = -1;

	}



	if(RegSetValueEx(hKey,szValueNameHASH,0,REG_DWORD,(const unsigned char *)szValueDataHASH,4)==ERROR_SUCCESS)
	{
		printf("创建REG_DWORD键值成功!\n");
	}
	else
	{
		printf("创建REG_DWORD键值失败!\n");
		iRet = -1;
	}
	if(RegSetValueEx(hKey,szValueNameSymmetric,0,REG_DWORD,(const unsigned char *)szValueDataSymmetric,4)==ERROR_SUCCESS)
	{
		printf("创建REG_DWORD键值成功!\n");
	}
	else
	{
		printf("创建REG_DWORD键值失败!\n");
		iRet = -1;

	}

	if(RegSetValueEx(hKey,szValueNameASymmetric,0,REG_DWORD,(const unsigned char *)szValueDataASymmetric,4)==ERROR_SUCCESS)
	{
		printf("创建REG_DWORD键值成功!\n");
	}
	else
	{
		printf("创建REG_DWORD键值失败!\n");
		iRet = -1;
	}

	RegCloseKey(hKey);

	return iRet;
}

int CRegOperation::Uninstall()
{
	int iRet = 0;

	if(ERROR_SUCCESS==RegDeleteKey(REG_ROOT_KEY,REG_SUB_KEY))
	{
		printf("删除子键成功!\n");
	}
	else
	{
		printf("删除子键失败!\n");
		iRet = -1;
	}

	return iRet;
}

int CRegOperation::Init()
{
	int iRet = 0;

	HKEY hKey;

	DWORD DataSize,MaxDateLen;
	DWORD dwIndex=0,NameSize,NameCnt,NameMaxLen,Type;

	LPCTSTR SubKey = REG_SUB_KEY;

	char * szValueName;
	LPBYTE  szValueData;

	if (RegOpenKeyEx(REG_ROOT_KEY,SubKey,0,KEY_ALL_ACCESS,&hKey)!=
		ERROR_SUCCESS)
	{
		printf("RegOpenKeyEx错误");
		iRet = -1;
	}
	//获取子键信息---------------------------------------------------------------
	if(RegQueryInfoKey(hKey,NULL,NULL,NULL,NULL,NULL,NULL,&NameCnt,&NameMaxLen,&MaxDateLen,NULL,NULL)!=ERROR_SUCCESS)
	{
		printf("RegQueryInfoKey错误");
		::RegCloseKey(hKey);
		iRet = -1;
	}
	//枚举键值信息---------------------------------------------------------------
	for(dwIndex=0;dwIndex<NameCnt;dwIndex++)    //枚举键值
	{
		DataSize=MaxDateLen+1;
		NameSize=NameMaxLen+1;
		szValueName=(char *)malloc(NameSize);
		szValueData=(LPBYTE)malloc(DataSize);

		memset(szValueName, 0, NameSize);
		memset(szValueData, 0, DataSize);

		RegEnumValue(hKey,dwIndex,szValueName,&NameSize,NULL,&Type,szValueData,&DataSize);//读取键值

		if(0 == (strcmp(szValueName,REG_VALUE_NAME_HASH)))
		{
			m_uHASH = /*atoi((const char *)szValueData)*/ (*(int *)(szValueData));
			printf("%d\n", m_uHASH);
		}
		else if(0 == (strcmp(szValueName,REG_VALUE_NAME_Symmetric)))
		{
			m_uSymmetric = /*atoi((const char *)szValueData)*/ (*(int *)(szValueData));
			printf("%d\n", m_uSymmetric);
		}   
		else if(0 == (strcmp(szValueName,REG_VALUE_NAME_ASymmetric)))
		{
			m_uASymmetric = /*atoi((const char *)szValueData)*/ (*(int *)(szValueData));
			printf("%d\n", m_uASymmetric);
		}

		else if(0 == (strcmp(szValueName,REG_VALUE_NAME_RootCert)))
		{
			if(NULL != m_pRootCert)
			{
				free(m_pRootCert);
				m_pRootCert = 0;
				m_iRootCertLength = 0;
			}
			m_iRootCertLength = DataSize;
			m_pRootCert = (unsigned char *)malloc(m_iRootCertLength);
			memcpy(m_pRootCert, szValueData, m_iRootCertLength);

			printf("%s %s\n", szValueName, m_pRootCert);
		}
		else if(0 == (strcmp(szValueName,REG_VALUE_NAME_SelfCert)))
		{
			if(NULL != m_pSelfCert)
			{
				free(m_pSelfCert);
				m_pSelfCert = 0;
				m_iSelfCertLength = 0;
			}
			m_iSelfCertLength = DataSize;
			m_pSelfCert = (unsigned char *)malloc(m_iSelfCertLength);
			memcpy(m_pSelfCert, szValueData, m_iSelfCertLength);

			printf("%s %s\n", szValueName, m_pSelfCert);
		}
		else if(0 == (strcmp(szValueName,REG_VALUE_NAME_PrivateKey)))
		{
			if(NULL != m_pPrivateKey)
			{
				free(m_pPrivateKey);
				m_pPrivateKey = 0;
				m_iPrivateKeyLength = 0;
			}
			m_iPrivateKeyLength = DataSize;
			m_pPrivateKey = (unsigned char *)malloc(m_iPrivateKeyLength);
			memcpy(m_pPrivateKey, szValueData, m_iPrivateKeyLength);

			printf("%s %s\n", szValueName, m_pPrivateKey);

		}

		free(szValueName);
		free(szValueData);
		szValueName = 0;
		szValueData = 0;
	}

	RegCloseKey(hKey);

	return iRet;
}


int CRegOperation::GetRootCertLength(int * pOutPutLength)
{
	int iRet = 0; 

	*pOutPutLength = m_iRootCertLength;

	return iRet;
}

int CRegOperation::GetSelfCertLength(int * pOutPutLength)
{
	int iRet = 0; 

	*pOutPutLength = m_iSelfCertLength;

	return iRet;
}

int CRegOperation::GetPrivateKeyLength(int * pOutPutLength)
{
	int iRet = 0; 

	*pOutPutLength = m_iPrivateKeyLength;

	return iRet;
}

int CRegOperation::GetRootCertWithLength(unsigned char * pOutPutData, int * pOutPutLength, int bFlag)
{
	int iRet = 0; 

	if(bFlag == 0)
	{
		HKEY hKey;

		DWORD DataSize,MaxDateLen;
		DWORD dwIndex=0,NameSize,NameCnt,NameMaxLen,Type;

		LPCTSTR SubKey = REG_SUB_KEY;

		char * szValueName;
		LPBYTE  szValueData;

		if (RegOpenKeyEx(REG_ROOT_KEY,SubKey,0,KEY_ALL_ACCESS,&hKey)!=
			ERROR_SUCCESS)
		{
			printf("RegOpenKeyEx错误");
			iRet = -1;
		}
		//获取子键信息---------------------------------------------------------------
		if(RegQueryInfoKey(hKey,NULL,NULL,NULL,NULL,NULL,NULL,&NameCnt,&NameMaxLen,&MaxDateLen,NULL,NULL)!=ERROR_SUCCESS)
		{
			printf("RegQueryInfoKey错误");
			::RegCloseKey(hKey);
			iRet = -1;
		}
		//枚举键值信息---------------------------------------------------------------
		for(dwIndex=0;dwIndex<NameCnt;dwIndex++)    //枚举键值
		{
			DataSize=MaxDateLen+1;
			NameSize=NameMaxLen+1;
			szValueName=(char *)malloc(NameSize);
			szValueData=(LPBYTE)malloc(DataSize);

			memset(szValueName, 0, NameSize);
			memset(szValueData, 0, DataSize);

			RegEnumValue(hKey,dwIndex,szValueName,&NameSize,NULL,&Type,szValueData,&DataSize);//读取键值

			if(0 == (strcmp(szValueName,REG_VALUE_NAME_RootCert)))
			{
				if(NULL != m_pRootCert)
				{
					free(m_pRootCert);
					m_pRootCert = 0;
					m_iRootCertLength = 0;
				}
				m_iRootCertLength = DataSize;
				m_pRootCert = (unsigned char *)malloc(m_iRootCertLength);
				memcpy(m_pRootCert, szValueData, m_iRootCertLength);

				printf("%s %s\n", szValueName, m_pRootCert);
			}

			free(szValueName);
			free(szValueData);
			szValueName = 0;
			szValueData = 0;
		}

		RegCloseKey(hKey);
	}

	memcpy(pOutPutData, m_pRootCert, m_iRootCertLength);
	*pOutPutLength = m_iRootCertLength;

	return iRet;
}

int CRegOperation::GetSelfCertWithLength(unsigned char * pOutPutData, int * pOutPutLength, int bFlag)
{
	int iRet = 0; 

	if(bFlag == 0)
	{
		HKEY hKey;

		DWORD DataSize,MaxDateLen;
		DWORD dwIndex=0,NameSize,NameCnt,NameMaxLen,Type;

		LPCTSTR SubKey = REG_SUB_KEY;

		char * szValueName;
		LPBYTE  szValueData;

		if (RegOpenKeyEx(REG_ROOT_KEY,SubKey,0,KEY_ALL_ACCESS,&hKey)!=
			ERROR_SUCCESS)
		{
			printf("RegOpenKeyEx错误");
			iRet = -1;
		}
		//获取子键信息---------------------------------------------------------------
		if(RegQueryInfoKey(hKey,NULL,NULL,NULL,NULL,NULL,NULL,&NameCnt,&NameMaxLen,&MaxDateLen,NULL,NULL)!=ERROR_SUCCESS)
		{
			printf("RegQueryInfoKey错误");
			::RegCloseKey(hKey);
			iRet = -1;
		}
		//枚举键值信息---------------------------------------------------------------
		for(dwIndex=0;dwIndex<NameCnt;dwIndex++)    //枚举键值
		{
			DataSize=MaxDateLen+1;
			NameSize=NameMaxLen+1;
			szValueName=(char *)malloc(NameSize);
			szValueData=(LPBYTE)malloc(DataSize);

			memset(szValueName, 0, NameSize);
			memset(szValueData, 0, DataSize);

			RegEnumValue(hKey,dwIndex,szValueName,&NameSize,NULL,&Type,szValueData,&DataSize);//读取键值

			if(0 == (strcmp(szValueName,REG_VALUE_NAME_SelfCert)))
			{
				if(NULL != m_pSelfCert)
				{
					free(m_pSelfCert);
					m_pSelfCert = 0;
					m_iSelfCertLength = 0;
				}
				m_iSelfCertLength = DataSize;
				m_pSelfCert = (unsigned char *)malloc(m_iSelfCertLength);
				memcpy(m_pSelfCert, szValueData, m_iSelfCertLength);

				printf("%s %s\n", szValueName, m_pSelfCert);
			}

			free(szValueName);
			free(szValueData);
			szValueName = 0;
			szValueData = 0;
		}

		RegCloseKey(hKey);
	}

	memcpy(pOutPutData, m_pSelfCert, m_iSelfCertLength);
	*pOutPutLength = m_iSelfCertLength;

	return iRet;
}

int CRegOperation::GetPrivateKeyWithLength(unsigned char * pOutPutData, int * pOutPutLength, int bFlag)
{
	int iRet = 0; 

	if(bFlag == 0)
	{
		HKEY hKey;

		DWORD DataSize,MaxDateLen;
		DWORD dwIndex=0,NameSize,NameCnt,NameMaxLen,Type;

		LPCTSTR SubKey = REG_SUB_KEY;

		char * szValueName;
		LPBYTE  szValueData;

		if (RegOpenKeyEx(REG_ROOT_KEY,SubKey,0,KEY_ALL_ACCESS,&hKey)!=
			ERROR_SUCCESS)
		{
			printf("RegOpenKeyEx错误");
			iRet = -1;
		}
		//获取子键信息---------------------------------------------------------------
		if(RegQueryInfoKey(hKey,NULL,NULL,NULL,NULL,NULL,NULL,&NameCnt,&NameMaxLen,&MaxDateLen,NULL,NULL)!=ERROR_SUCCESS)
		{
			printf("RegQueryInfoKey错误");
			::RegCloseKey(hKey);
			iRet = -1;
		}
		//枚举键值信息---------------------------------------------------------------
		for(dwIndex=0;dwIndex<NameCnt;dwIndex++)    //枚举键值
		{
			DataSize=MaxDateLen+1;
			NameSize=NameMaxLen+1;
			szValueName=(char *)malloc(NameSize);
			szValueData=(LPBYTE)malloc(DataSize);

			memset(szValueName, 0, NameSize);
			memset(szValueData, 0, DataSize);

			RegEnumValue(hKey,dwIndex,szValueName,&NameSize,NULL,&Type,szValueData,&DataSize);//读取键值

			if(0 == (strcmp(szValueName,REG_VALUE_NAME_PrivateKey)))
			{
				if(NULL != m_pPrivateKey)
				{
					free(m_pPrivateKey);
					m_pPrivateKey = 0;
					m_iPrivateKeyLength = 0;
				}
				m_iPrivateKeyLength = DataSize;
				m_pPrivateKey = (unsigned char *)malloc(m_iPrivateKeyLength);
				memcpy(m_pPrivateKey, szValueData, m_iPrivateKeyLength);

				printf("%s %s\n", szValueName, m_pPrivateKey);

			}

			free(szValueName);
			free(szValueData);
			szValueName = 0;
			szValueData = 0;
		}

		RegCloseKey(hKey);
	}

	memcpy(pOutPutData, m_pPrivateKey, m_iPrivateKeyLength);
	*pOutPutLength = m_iPrivateKeyLength;

	return iRet;
}


int CRegOperation::SetRootCertWithLength(unsigned char * pInPutData, int iInputLength, int bFlag)
{
	int iRet = 0; 

	if(bFlag == 0)
	{
		HKEY hKey;

		LPCTSTR SubKey = REG_SUB_KEY;

		char *szValueNameRootCert = REG_VALUE_NAME_RootCert;
		char *szValueDataRootCert = (char *)pInPutData;
		int cbLenRootCert = iInputLength;

		if (RegOpenKeyEx(REG_ROOT_KEY,SubKey,0,KEY_ALL_ACCESS,&hKey)!=
			ERROR_SUCCESS)
		{
			printf("RegOpenKeyEx错误");
			iRet = -1;
		}

		if(RegSetValueEx(hKey,szValueNameRootCert,0,REG_BINARY,(const unsigned char *)szValueDataRootCert,cbLenRootCert)==ERROR_SUCCESS)
		{
			printf("创建REG_BINARY键值成功!\n");
		}
		else
		{
			printf("创建REG_BINARY键值失败!\n");
			iRet = -1;
		}


		RegCloseKey(hKey);
	}

	if(NULL != m_pRootCert)
	{
		free(m_pRootCert);
		m_pRootCert = 0;
		m_iRootCertLength = 0;
	}

	m_iRootCertLength = iInputLength;
	m_pRootCert = (unsigned char *)malloc(m_iRootCertLength);
	memcpy(m_pRootCert, pInPutData, m_iRootCertLength);


	return iRet;
}

int CRegOperation::SetSelfCertWithLength(unsigned char * pInPutData, int iInputLength, int bFlag)
{
	int iRet = 0; 

	if(bFlag == 0)
	{
		HKEY hKey;

		LPCTSTR SubKey = REG_SUB_KEY;

		char *szValueNameSelfCert = REG_VALUE_NAME_SelfCert;
		char *szValueDataSelfCert = (char *)pInPutData;
		int cbLenSelfCert = iInputLength;

		if (RegOpenKeyEx(REG_ROOT_KEY,SubKey,0,KEY_ALL_ACCESS,&hKey)!=
			ERROR_SUCCESS)
		{
			printf("RegOpenKeyEx错误");
			iRet = -1;
		}

		if(RegSetValueEx(hKey,szValueNameSelfCert,0,REG_BINARY,(const unsigned char *)szValueDataSelfCert,cbLenSelfCert)==ERROR_SUCCESS)
		{
			printf("创建REG_BINARY键值成功!\n");
		}
		else
		{
			printf("创建REG_BINARY键值失败!\n");
			iRet = -1;
		}


		RegCloseKey(hKey);
	}

	if(NULL != m_pSelfCert)
	{
		free(m_pSelfCert);
		m_pSelfCert = 0;
		m_iSelfCertLength = 0;
	}

	m_iSelfCertLength = iInputLength;
	m_pSelfCert = (unsigned char *)malloc(m_iSelfCertLength);
	memcpy(m_pSelfCert, pInPutData, m_iSelfCertLength);


	return iRet;
}

int CRegOperation::SetPrivateKeyWithLength(unsigned char * pInPutData, int iInputLength, int bFlag)
{
	int iRet = 0; 

	if(bFlag == 0)
	{
		HKEY hKey;

		LPCTSTR SubKey = REG_SUB_KEY;

		char *szValueNamePrivateKey = REG_VALUE_NAME_PrivateKey;
		char *szValueDataPrivateKey = (char *)pInPutData;
		int cbLenPrivateKey = iInputLength;

		if (RegOpenKeyEx(REG_ROOT_KEY,SubKey,0,KEY_ALL_ACCESS,&hKey)!=
			ERROR_SUCCESS)
		{
			printf("RegOpenKeyEx错误");
			iRet = -1;
		}

		if(RegSetValueEx(hKey,szValueNamePrivateKey,0,REG_BINARY,(const unsigned char *)szValueDataPrivateKey,cbLenPrivateKey)==ERROR_SUCCESS)
		{
			printf("创建REG_BINARY键值成功!\n");
		}
		else
		{
			printf("创建REG_BINARY键值失败!\n");
			iRet = -1;
		}


		RegCloseKey(hKey);
	}

	if(NULL != m_pPrivateKey)
	{
		free(m_pPrivateKey);
		m_pPrivateKey = 0;
		m_iPrivateKeyLength = 0;
	}

	m_iPrivateKeyLength = iInputLength;
	m_pPrivateKey = (unsigned char *)malloc(m_iPrivateKeyLength);
	memcpy(m_pPrivateKey, pInPutData, m_iPrivateKeyLength);


	return iRet;
}


int CRegOperation::GetHASH(DWORD * pOutPut, int bFlag)
{
	int iRet = 0; 

	if(bFlag == 0)
	{
		HKEY hKey;

		DWORD DataSize,MaxDateLen;
		DWORD dwIndex=0,NameSize,NameCnt,NameMaxLen,Type;

		LPCTSTR SubKey = REG_SUB_KEY;

		char * szValueName;
		LPBYTE  szValueData;

		if (RegOpenKeyEx(REG_ROOT_KEY,SubKey,0,KEY_ALL_ACCESS,&hKey)!=
			ERROR_SUCCESS)
		{
			printf("RegOpenKeyEx错误");
			iRet = -1;
		}
		//获取子键信息---------------------------------------------------------------
		if(RegQueryInfoKey(hKey,NULL,NULL,NULL,NULL,NULL,NULL,&NameCnt,&NameMaxLen,&MaxDateLen,NULL,NULL)!=ERROR_SUCCESS)
		{
			printf("RegQueryInfoKey错误");
			::RegCloseKey(hKey);
			iRet = -1;
		}
		//枚举键值信息---------------------------------------------------------------
		for(dwIndex=0;dwIndex<NameCnt;dwIndex++)    //枚举键值
		{
			DataSize=MaxDateLen+1;
			NameSize=NameMaxLen+1;
			szValueName=(char *)malloc(NameSize);
			szValueData=(LPBYTE)malloc(DataSize);

			memset(szValueName, 0, NameSize);
			memset(szValueData, 0, DataSize);

			RegEnumValue(hKey,dwIndex,szValueName,&NameSize,NULL,&Type,szValueData,&DataSize);//读取键值

			if(0 == (strcmp(szValueName,REG_VALUE_NAME_HASH)))
			{
				m_uHASH = /*atoi((const char *)szValueData)*/ (*(int *)(szValueData));
				printf("%d\n", m_uHASH);
			}

			free(szValueName);
			free(szValueData);
			szValueName = 0;
			szValueData = 0;
		}

		RegCloseKey(hKey);
	}

	* pOutPut = m_uHASH;

	return iRet;
}

int CRegOperation::GetSymmetric(DWORD * pOutPut, int bFlag)
{
	int iRet = 0; 

	if(bFlag == 0)
	{
		HKEY hKey;

		DWORD DataSize,MaxDateLen;
		DWORD dwIndex=0,NameSize,NameCnt,NameMaxLen,Type;

		LPCTSTR SubKey = REG_SUB_KEY;

		char * szValueName;
		LPBYTE  szValueData;

		if (RegOpenKeyEx(REG_ROOT_KEY,SubKey,0,KEY_ALL_ACCESS,&hKey)!=
			ERROR_SUCCESS)
		{
			printf("RegOpenKeyEx错误");
			iRet = -1;
		}
		//获取子键信息---------------------------------------------------------------
		if(RegQueryInfoKey(hKey,NULL,NULL,NULL,NULL,NULL,NULL,&NameCnt,&NameMaxLen,&MaxDateLen,NULL,NULL)!=ERROR_SUCCESS)
		{
			printf("RegQueryInfoKey错误");
			::RegCloseKey(hKey);
			iRet = -1;
		}
		//枚举键值信息---------------------------------------------------------------
		for(dwIndex=0;dwIndex<NameCnt;dwIndex++)    //枚举键值
		{
			DataSize=MaxDateLen+1;
			NameSize=NameMaxLen+1;
			szValueName=(char *)malloc(NameSize);
			szValueData=(LPBYTE)malloc(DataSize);

			memset(szValueName, 0, NameSize);
			memset(szValueData, 0, DataSize);

			RegEnumValue(hKey,dwIndex,szValueName,&NameSize,NULL,&Type,szValueData,&DataSize);//读取键值

			if(0 == (strcmp(szValueName,REG_VALUE_NAME_Symmetric)))
			{
				m_uSymmetric = /*atoi((const char *)szValueData)*/ (*(int *)(szValueData));
				printf("%d\n", m_uSymmetric);
			}   

			free(szValueName);
			free(szValueData);
			szValueName = 0;
			szValueData = 0;
		}

		RegCloseKey(hKey);
	}

	*pOutPut = m_uSymmetric;

	return iRet;
}
int CRegOperation::GetASymmetric(DWORD * pOutPut, int bFlag)
{
	int iRet = 0; 

	if(bFlag == 0)
	{
		HKEY hKey;

		DWORD DataSize,MaxDateLen;
		DWORD dwIndex=0,NameSize,NameCnt,NameMaxLen,Type;

		LPCTSTR SubKey = REG_SUB_KEY;

		char * szValueName;
		LPBYTE  szValueData;

		if (RegOpenKeyEx(REG_ROOT_KEY,SubKey,0,KEY_ALL_ACCESS,&hKey)!=
			ERROR_SUCCESS)
		{
			printf("RegOpenKeyEx错误");
			iRet = -1;
		}
		//获取子键信息---------------------------------------------------------------
		if(RegQueryInfoKey(hKey,NULL,NULL,NULL,NULL,NULL,NULL,&NameCnt,&NameMaxLen,&MaxDateLen,NULL,NULL)!=ERROR_SUCCESS)
		{
			printf("RegQueryInfoKey错误");
			::RegCloseKey(hKey);
			iRet = -1;
		}
		//枚举键值信息---------------------------------------------------------------
		for(dwIndex=0;dwIndex<NameCnt;dwIndex++)    //枚举键值
		{
			DataSize=MaxDateLen+1;
			NameSize=NameMaxLen+1;
			szValueName=(char *)malloc(NameSize);
			szValueData=(LPBYTE)malloc(DataSize);

			memset(szValueName, 0, NameSize);
			memset(szValueData, 0, DataSize);

			RegEnumValue(hKey,dwIndex,szValueName,&NameSize,NULL,&Type,szValueData,&DataSize);//读取键值

			if(0 == (strcmp(szValueName,REG_VALUE_NAME_ASymmetric)))
			{
				m_uASymmetric = /*atoi((const char *)szValueData)*/ (*(int *)(szValueData));
				printf("%d\n", m_uASymmetric);
			}

			free(szValueName);
			free(szValueData);
			szValueName = 0;
			szValueData = 0;
		}

		RegCloseKey(hKey);
	}

	*pOutPut = m_uASymmetric;

	return iRet;
}

int CRegOperation::SetHASH(DWORD dwInput,int bFlag)
{
	int iRet = 0; 

	if(bFlag == 0)
	{
		HKEY hKey;

		LPCTSTR SubKey = REG_SUB_KEY;

		char *szValueNameHASH = REG_VALUE_NAME_HASH;
		UINT uHASH = dwInput;
		UINT *szValueDataHASH = &uHASH;

		if (RegOpenKeyEx(REG_ROOT_KEY,SubKey,0,KEY_ALL_ACCESS,&hKey)!=
			ERROR_SUCCESS)
		{
			printf("RegOpenKeyEx错误");
			iRet = -1;
		}

		if(RegSetValueEx(hKey,szValueNameHASH,0,REG_DWORD,(const unsigned char *)szValueDataHASH,4)==ERROR_SUCCESS)
		{
			printf("创建REG_DWORD键值成功!\n");
		}
		else
		{
			printf("创建REG_DWORD键值失败!\n");
			iRet = -1;
		}

		RegCloseKey(hKey);
	}

	m_uHASH = dwInput;

	return iRet;
}

int CRegOperation::SetSymmetric(DWORD dwInput, int bFlag)
{
	int iRet = 0; 

	if(bFlag == 0)
	{
		HKEY hKey;

		LPCTSTR SubKey = REG_SUB_KEY;

		char *szValueNameSymmetric = REG_VALUE_NAME_Symmetric;
		UINT uSymmetric = dwInput;
		UINT *szValueDataSymmetric = &uSymmetric;


		if (RegOpenKeyEx(REG_ROOT_KEY,SubKey,0,KEY_ALL_ACCESS,&hKey)!=
			ERROR_SUCCESS)
		{
			printf("RegOpenKeyEx错误");
			iRet = -1;
		}

		if(RegSetValueEx(hKey,szValueNameSymmetric,0,REG_DWORD,(const unsigned char *)szValueDataSymmetric,4)==ERROR_SUCCESS)
		{
			printf("创建REG_DWORD键值成功!\n");
		}
		else
		{
			printf("创建REG_DWORD键值失败!\n");
			iRet = -1;

		}

		RegCloseKey(hKey);
	}

	m_uSymmetric = dwInput;

	return iRet;
}

int CRegOperation::SetASymmetric(DWORD dwInput, int bFlag)
{
	int iRet = 0; 

	if(bFlag == 0)
	{
		HKEY hKey;

		char *szValueNameASymmetric = REG_VALUE_NAME_ASymmetric;
		UINT uASymmetric = dwInput;
		UINT *szValueDataASymmetric = &uASymmetric;

		LPCTSTR SubKey = REG_SUB_KEY;


		if (RegOpenKeyEx(REG_ROOT_KEY,SubKey,0,KEY_ALL_ACCESS,&hKey)!=
			ERROR_SUCCESS)
		{
			printf("RegOpenKeyEx错误");
			iRet = -1;
		}
		if(RegSetValueEx(hKey,szValueNameASymmetric,0,REG_DWORD,(const unsigned char *)szValueDataASymmetric,4)==ERROR_SUCCESS)
		{
			printf("创建REG_DWORD键值成功!\n");
		}
		else
		{
			printf("创建REG_DWORD键值失败!\n");
			iRet = -1;
		}


		RegCloseKey(hKey);
	}

	m_uASymmetric = dwInput;

	return iRet;
}
