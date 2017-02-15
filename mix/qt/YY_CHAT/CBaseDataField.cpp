/*
 * CBaseDataField.cpp
 *
 *  Created on: 2012-1-13
 *      Author: Administrator
 */

#include "CBaseDataField.h"
#include <string.h>

CBaseDataField::CBaseDataField(const char * aStr, int aLen, int aName) :
    CBaseData()
{
    // TODO Auto-generated constructor stub
    iName = aName;
    SetValue(aStr, aLen);
}

CBaseDataField::CBaseDataField(int aName) :
    CBaseData()
{
    // TODO Auto-generated constructor stub
    iName = aName;
}

CBaseDataField::CBaseDataField(const CBaseDataField &aRhs)
{
    iName = aRhs.iName;
    SetValue(aRhs.iData, aRhs.iLen);
}

CBaseDataField::~CBaseDataField()
{
    // TODO Auto-generated destructor stub
    iName = 0;
}

bool CBaseDataField::SetValue(const char * aStr, int aLen)
{
	if (NULL != iData)
	{
		delete iData;
		iData = 0;
	}

    iData = new char[aLen];
    if (!iData) {
        return false;
    }

    iLen = aLen;
    memset(iData, 0, aLen);
    memcpy(iData, aStr, aLen);
}

bool CBaseDataField::SetName(int aName)
{
    iName = aName;
}

const char *CBaseDataField::GetValue(void) const
{
    return iData;
}

long long CBaseDataField::GetLength(void) const
{
    return iLen;
}

int CBaseDataField::GetName(void) const
{
    return iName;
}
