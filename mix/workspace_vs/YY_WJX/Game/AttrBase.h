#ifndef ATTRBASE_H
#define ATTRBASE_H

#include "common.h"
#include "Base.h"

class CAttrBase:
	public CBase
{
public:
	CAttrBase(void);
	virtual ~CAttrBase(void);

	int GetElement(int i= 0);
	void SetElement(int i = 0, int value = 0);
	void ShowAllElement();

protected:



private:
	int m_Element[ELE_LEN];                       //::ʮԪ�����ԣ���ľˮ�������׹ⰵ���
};


#endif