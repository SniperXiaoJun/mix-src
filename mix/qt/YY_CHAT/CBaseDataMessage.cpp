/*
 * CBaseDataMessage.cpp
 *
 *  Created on: 2012-1-16
 *      Author: Administrator
 */

#include "CBaseDataMessage.h"
#include <stdio.h>

CBaseDataMessage::CBaseDataMessage(const char *aValue, int aLen, int aName) :
    CBaseDataField(aValue, aLen, aName)
{
    iPos = 0;
}

CBaseDataMessage::CBaseDataMessage(const CBaseDataMessage & aRhs) :
    CBaseDataField(aRhs.iData, aRhs.iLen, aRhs.iName), iMapNameNum(aRhs.iMapNameNum), iMapNamePos(
        aRhs.iMapNamePos), iPos(aRhs.iPos)
{
    for (int i = 0; i < aRhs.iVecMSG.size(); i++) {
        iVecMSG.push_back(new CBaseDataField(*aRhs.iVecMSG[i]));
    }
}

CBaseDataMessage::~CBaseDataMessage()
{
    for (int i = 0; i < iVecMSG.size(); i++) {
        delete iVecMSG[i];
        iVecMSG[i] = NULL;
    }

    iVecMSG.clear();
}

bool CBaseDataMessage::AddField(const CBaseDataField &aField)
{
    CBaseDataField *pFld = new CBaseDataField(aField);
    iVecMSG.push_back(pFld); //将字段填入m_vecMsgEntity中

    //查看是否有相同字段名的field存在，返回在m_vecMsgEntity中字段名为field.GetName的个数
    char szFieldCount[100];
    int ulFieldCount = (0 == iMapNameNum.count(aField.GetName())) ? 0
        : iMapNameNum[aField.GetName()];
    sprintf(szFieldCount, "%d %d", aField.GetName(), ulFieldCount);

    //记录字段field在m_vecMsgEntity中的位置,m_mapNamePos中元素的结构为"Name Count, Pos"，Count相当于第几个放入m_vecMsgEntity的Name
    iMapNamePos[szFieldCount] = iPos++;

    //记录字段名为field.GetName的字段个数
    iMapNameNum[aField.GetName()] = ulFieldCount + 1;

    return true;
}

int CBaseDataMessage::GetFieldNumber() const
{
    return iVecMSG.size();
}

int CBaseDataMessage::GetFieldNumber(int aName) const
{
    return ((map<int, int> ) iMapNameNum)[aName];
}

bool CBaseDataMessage::CheckField(int aName)
{
    if (0 == iMapNameNum.count(aName) || 0 == iMapNameNum[aName]) {
        return false;
    }
    else {
        return true;
    }
}

const CBaseDataField &CBaseDataMessage::GetField(int aName, int aPos) const
{
    if (0 == iMapNameNum.count(aName) || aPos >= ((map<int, int>)iMapNameNum)[aName]) {
        ;
    }

    char szPos[100];
    sprintf(szPos, "%d %d", aName, aPos);

    //先获取根据iName和ulPos获取字段在m_vecMsgEntity中的位置，再从m_vecMsgEntity中取出值
    return *iVecMSG[((map<string, int>)iMapNamePos)[szPos]];
}

bool CBaseDataMessage::DelField(int aName, int aPos)
{
    if (0 == iMapNameNum.count(aName) || aPos >= iMapNameNum[aName]) {
        return false;
    }

    char szPosPre[100], szPosNext[100];

    for (; aPos < iMapNameNum[aName] - 1; aPos++) {
        sprintf(szPosPre, "%d %d", aName, aPos);
        sprintf(szPosNext, "%d %d", aName, aPos + 1);

        iMapNamePos[szPosPre] = iMapNamePos[szPosNext];
    }
    iMapNameNum[aName]--;

    return true;
}

bool CBaseDataMessage::DelFieldAll()
{
    for (int i = 0; i < iVecMSG.size(); i++) {
        delete iVecMSG[i];
        iVecMSG[i] = NULL;
    }

    iVecMSG.clear();

    iPos = 0;
    iMapNamePos.clear();
    iMapNameNum.clear();

    return true;
}

bool CBaseDataMessage::ModField(const CBaseDataField & aField, int aPos)
{
    if (0 == iMapNameNum.count(aField.GetName()) || aPos >= iMapNameNum[aField.GetName()]) {
        return false;
    }

    char szPos[100];
    sprintf(szPos, "%d %d", aField.GetName(), aPos);
    iVecMSG[iMapNamePos[szPos]]->SetValue(aField.GetValue(), aField.GetLength());

    return true;
}

int CBaseDataMessage::PackMsg(void)
{
    return 0;
}

int CBaseDataMessage::ParseMsg(void)
{
    return 0;
}

const char *CBaseDataMessage::GetMsgText(void) const
{
    return iData;
}

int CBaseDataMessage::GetMsgLen(void) const
{
    return iLen;
}

CBaseDataField *CBaseDataMessage::CreateField(const CBaseDataField & aField)
{
    return new CBaseDataField(aField);
}

const CBaseDataField & CBaseDataMessage::operator [](int aNum) const
{
    if (aNum > iVecMSG.size()) {
        ;
    }

    return *iVecMSG[aNum];
}

