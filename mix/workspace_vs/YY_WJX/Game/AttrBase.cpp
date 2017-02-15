#include "AttrBase.h"
#include "stdio.h"

CAttrBase::CAttrBase(void)
{
	for(int i = NUMBER_0; i < ELE_LEN; i++)
	{
		m_Element[i] = NUMBER_1;
	}

}

CAttrBase::~CAttrBase(void)
{

}

int CAttrBase::GetElement(int i)
{
	return m_Element[i];
}

void CAttrBase::SetElement(int i, int value)
{
	m_Element[i] = value;
}

void CAttrBase::ShowAllElement()
{
	for(int i = 0; i < 10; i++)
	{
		printf("value[%d] = %d!\n",i,m_Element[i]);
	}
	
}
