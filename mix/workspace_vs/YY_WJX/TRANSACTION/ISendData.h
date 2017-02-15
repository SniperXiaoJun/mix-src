//-------------------------------------------------------------------------------------
// �ļ���: ISendData.h
// ������: Yan haicheng 
// ��  ��: 2010-08-03
// ��  ��: ͷ�ļ������巢�����ݳ�����
// ��  ��: 1.0
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
