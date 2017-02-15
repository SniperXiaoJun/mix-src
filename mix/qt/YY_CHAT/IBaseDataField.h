/*
 * IBaseDataField.h
 *
 *  Created on: 2012-1-13
 *      Author: Administrator
 */

#ifndef IBASEDATAFIELD_H_
#define IBASEDATAFIELD_H_

class IBaseDataField
{
public:
    virtual bool SetValue(const char * aStr, int aLen) = 0;
    virtual bool SetName(int aName) = 0;
    virtual const char *GetValue(void) const = 0;
    virtual long long GetLength(void) const = 0;
    virtual int GetName(void) const = 0;
};

#endif /* IBASEDATAFIELD_H_ */
