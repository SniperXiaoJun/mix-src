#ifndef BAGBASE_H
#define BAGBASE_H

#include "common.h"
#include "Base.h"
#include "ObjectBase.h"

class CBagBase: 
	public CBase
{
public:
	CBagBase(int con = 10);
	virtual ~CBagBase();

protected:

private:
	CObjectBase * m_pObj;
};

#endif