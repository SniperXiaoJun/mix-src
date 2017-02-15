#ifndef _DATA_H__
#define _DATA_H__

#include "../Common/common.h"

class CData
{
protected:

	CData(void);

	~CData(void);

protected:

	Byte *m_pValue;							//:: 字段数据字节流指针
	UInt32 m_uLen;							//:: 字段数据字节流长度	
};

#endif // !defined _DATA_H__