#ifndef _DATA_H__
#define _DATA_H__

#include "../Common/common.h"

class CData
{
protected:

	CData(void);

	~CData(void);

protected:

	Byte *m_pValue;							//:: �ֶ������ֽ���ָ��
	UInt32 m_uLen;							//:: �ֶ������ֽ�������	
};

#endif // !defined _DATA_H__