#ifndef USERBASE_H
#define USERBASE_H

#include "AttrBase.h"
#include "CoinBase.h"
#include "BagBase.h"
#include "Base.h"
#include "ExperBase.h"

class CUserBase:
	public CBase
{
public:
	CUserBase(void);
	virtual ~CUserBase(void);

protected:

private:
	CAttrBase m_Attr;
	CCoinBase m_Coin;
	CBagBase m_Bag;
	CExperBase m_Exp;
};

#endif