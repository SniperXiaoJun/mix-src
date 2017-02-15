/*
 * IBaseDataMessage.h
 *
 *  Created on: 2012-1-16
 *      Author: Administrator
 */

#ifndef IBASEDATAMESSAGE_H_
#define IBASEDATAMESSAGE_H_

#include "CBaseDataField.h"

class IBaseDataMessage
{
public:
    virtual bool AddField(const CBaseDataField &aField) = 0;
    virtual int GetFieldNumber() const = 0;
    virtual int GetFieldNumber(int aName) const = 0;
    virtual bool CheckField(int aName) = 0;
    virtual const CBaseDataField &GetField(int aName, int aPos = 0) const = 0;
    virtual bool DelField(int aName, int aPos = 0) = 0;
    virtual bool DelFieldAll() = 0;
    virtual bool ModField(const CBaseDataField & aField, int aPos = 0) = 0;
    virtual int PackMsg(void) = 0;
    virtual int ParseMsg(void) = 0;
    virtual const char *GetMsgText(void) const = 0;
    virtual int GetMsgLen(void) const = 0;
    virtual CBaseDataField *CreateField(const CBaseDataField & aField) = 0;
protected:
    virtual const CBaseDataField &operator [](int aNum) const = 0;
};

#endif /* IBASEDATAMESSAGE_H_ */
