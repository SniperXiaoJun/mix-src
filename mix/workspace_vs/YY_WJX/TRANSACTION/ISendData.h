//-------------------------------------------------------------------------------------
// 文件名: ISendData.h
// 创建人: Yan haicheng 
// 日  期: 2010-08-03
// 描  述: 头文件，定义发送数据抽象类
// 版  本: 1.0
//-------------------------------------------------------------------------------------

#ifndef _ISENDDATA_H__
#define _ISENDDATA_H__

#include <string>
using std::string;

#include "../Common/common.h"
#include "TransactionDll.h"

class ISendData
{
public:
	enum {NoErr = 0, SendErr};

	virtual int SendData(const Byte *pData, int iLen) = 0;
};

#endif
