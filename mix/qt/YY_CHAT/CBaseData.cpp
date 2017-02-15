/*
 * CBaseData.cpp
 *
 *  Created on: 2012-1-13
 *      Author: Administrator
 */

#include "CBaseData.h"

CBaseData::CBaseData()
{
    // TODO Auto-generated constructor stub
    iData = 0;
    iLen = 0;
}

CBaseData::~CBaseData()
{
    // TODO Auto-generated destructor stub
    delete[] iData;
    iData = 0;
    iLen = 0;
}
