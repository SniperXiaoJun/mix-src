//-------------------------------------------------------------------------------------
// 文件名: TranszctionDll.h
// 创建人: Yan haicheng 
// 日  期: 2010-08-03
// 描  述: 头文件，定义Transaction的导出
// 版  本: 1.0
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
