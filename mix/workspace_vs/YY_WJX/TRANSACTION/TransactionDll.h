//-------------------------------------------------------------------------------------
// �ļ���: TranszctionDll.h
// ������: Yan haicheng 
// ��  ��: 2010-08-03
// ��  ��: ͷ�ļ�������Transaction�ĵ���
// ��  ��: 1.0
//-------------------------------------------------------------------------------------

#ifdef TRANSACTION_EXPORTS
#define TRANSACTIONDLL_API __declspec(dllexport)
#else
#ifdef _WINDOWS
#define TRANSACTIONDLL_API __declspec(dllimport)
#else
#define TRANSACTIONDLL_API
#endif
#endif
