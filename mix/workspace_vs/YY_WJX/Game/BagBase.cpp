#include "BagBase.h"

CBagBase::CBagBase(int con)
{
	m_pObj = new CObjectBase[con];
}

CBagBase::~CBagBase(void)
{
	if(m_pObj)
	{
		delete[] m_pObj;
	}
}
