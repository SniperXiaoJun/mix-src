#pragma once

#ifdef REGOPERATIONINTERFACE_EXPORTS
#define REGOPERATIONINTERFACE_API __declspec(dllexport)
#else
#define REGOPERATIONINTERFACE_API __declspec(dllimport)
#endif

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#include "RegOperationDefine.h"


/*
所有函数返回值　为０正确　非０（－１）异常
bFlag 默认0 写注册表　非0　写内存
*/
class REGOPERATIONINTERFACE_API CRegOperation
{
public:
	CRegOperation(void);
	~CRegOperation(void);
	
	static int Installation();
	static int Uninstall();
	static CRegOperation * Instance();

	int Init();

	int GetRootCertLength(int * pOutPutLength);
	int GetSelfCertLength(int * pOutPutLength);
	int GetPrivateKeyLength(int * pOutPutLength);

	int GetRootCertWithLength(unsigned char * pOutPutData, int * pOutPutLength, int bFlag = 0);
	int GetSelfCertWithLength(unsigned char * pOutPutData, int * pOutPutLength, int bFlag = 0);
	int GetPrivateKeyWithLength(unsigned char * pOutPutData, int * pOutPutLength, int bFlag = 0);

	int SetRootCertWithLength(unsigned char * pInPutData, int iInputLength, int bFlag = 0);
	int SetSelfCertWithLength(unsigned char * pInPutData, int iInputLength, int bFlag = 0);
	int SetPrivateKeyWithLength(unsigned char * pInPutData, int iInputLength, int bFlag = 0);


	int GetHASH(DWORD * pOutPut,int bFlag = 0);
	int GetSymmetric(DWORD * pOutPut,int bFlag = 0);
	int GetASymmetric(DWORD * pOutPut,int bFlag = 0);

	int SetHASH(DWORD dwInput,int bFlag = 0);
	int SetSymmetric(DWORD dwInput, int bFlag = 0);
	int SetASymmetric(DWORD dwInput, int bFlag = 0);


private:
	unsigned char * m_pRootCert;
	int m_iRootCertLength;

	unsigned char * m_pSelfCert;
	int m_iSelfCertLength;

	unsigned char * m_pPrivateKey;
	int m_iPrivateKeyLength;

	DWORD m_uHASH;
	DWORD m_uSymmetric;
	DWORD m_uASymmetric;

	static CRegOperation * _instance;
};
