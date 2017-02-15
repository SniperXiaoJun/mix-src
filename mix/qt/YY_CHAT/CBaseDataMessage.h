/*
 * CBaseDataMessage.h
 *
 *  Created on: 2012-1-16
 *      Author: Administrator
 */

#ifndef CBASEDATAMESSAGE_H_
#define CBASEDATAMESSAGE_H_

#include "CBaseDataField.h"
#include "IBaseDataMessage.h"

#include <vector>
using std::vector;
#include <map>
using std::map;
#include <string>
using std::string;

class CBaseDataMessage: public CBaseDataField, public IBaseDataMessage
{
public:
    CBaseDataMessage(const char *aValue = 0, int aLen = 0, int aName = 0);
    CBaseDataMessage(const CBaseDataMessage & aRhs);

    virtual ~CBaseDataMessage();

    virtual bool AddField(const CBaseDataField &aField);
    virtual int GetFieldNumber() const;
    virtual int GetFieldNumber(int aName) const;
    virtual bool CheckField(int aName);
    virtual const CBaseDataField &GetField(int aName, int aPos) const;
    virtual bool DelField(int aName, int aPos = 0);
    virtual bool DelFieldAll();
    virtual bool ModField(const CBaseDataField & aField, int aPos);
    virtual int PackMsg(void);
    virtual int ParseMsg(void);
    virtual const char *GetMsgText(void) const;
    virtual int GetMsgLen(void) const;
    virtual CBaseDataField *CreateField(const CBaseDataField & aField);
protected:
    virtual const CBaseDataField &operator [](int aNum) const;

protected:
    vector<CBaseDataField *> iVecMSG;  //:: 消息字段指针向量,存放UAPMsg中的所有Field字段
    int iPos;                            //:: 消息字段位置，指向iVecMSG中最后一个元素的位置？
    map<string, int> iMapNamePos;        //:: 消息字段名映射，Field在iVecMSG位置
    map<int, int> iMapNameNum;           //:: 消息字段名个数
};

#endif /* CBASEDATAMESSAGE_H_ */
