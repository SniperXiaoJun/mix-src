/*
 * CBaseDataField.h
 *
 *  Created on: 2012-1-13
 *      Author: Administrator
 */

#ifndef CBASEDATAFIELD_H_
#define CBASEDATAFIELD_H_

#include "IBaseDataField.h"
#include "CBaseData.h"

class CBaseDataField: public IBaseDataField, public CBaseData
{
public:
    CBaseDataField(const char * aStr = 0, int aLen = 0, int aName = 0);
    CBaseDataField(int aName);
    CBaseDataField(const CBaseDataField &aRhs);
    virtual ~CBaseDataField();

    bool SetValue(const char * aStr, int aLen);
    bool SetName(int aName);
    const char *GetValue(void) const;
    long long GetLength(void) const;
    int GetName(void) const;
protected:
    int iName;
};

#endif /* CBASEDATAFIELD_H_ */
