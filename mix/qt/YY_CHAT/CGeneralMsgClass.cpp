/*
 * CBankMsg.cpp
 *
 *  Created on: 2011-9-26
 *      Author: Administrator
 */

#include "CGeneralMsgClass.h"
#include <string.h>

CGeneralMsgClass::CGeneralMsgClass(const char *pValue, int ulLen) :
    CBaseDataMessage(pValue, ulLen)
{
    // TODO Auto-generated constructor stub
}

CGeneralMsgClass::~CGeneralMsgClass()
{
    // TODO Auto-generated destructor stub
}

int CGeneralMsgClass::PackMsg(void)
{
    int iLength = 0; // 总域的的个数
    int iPos = 0; // 位置

    iLen = 0;

    for (int iName = 0; iName < EFIELD_NAME_USR_COUNT; iName++) {
        iLength = GetFieldNumber(iName);
        for (iPos = 0; iPos < iLength; iPos++) {
            iLen += sizeof(SGeneralMsgStruct);
            iLen += GetField(iName, iPos).GetLength();
        }
    }

    delete[] iData;
    iData = new char[iLen];
    iLen = 0;

    for (int iName = 0; iName < EFIELD_NAME_USR_COUNT; iName++) {
        iLength = GetFieldNumber(iName);
        for (iPos = 0; iPos < iLength; iPos++) {
            CBaseDataField fieldPro(USR_NAME);
            SGeneralMsgStruct structPro;
            const CBaseDataField &field = GetField(iName, iPos);

            structPro.length = field.GetLength();
            structPro.name = field.GetName();
            fieldPro.SetValue((char *) (&structPro), sizeof(SGeneralMsgStruct));

            memcpy(iData + iLen, fieldPro.GetValue(), fieldPro.GetLength());
            iLen += fieldPro.GetLength();

            memcpy(iData + iLen, field.GetValue(), field.GetLength());
            iLen += field.GetLength();
        }
    }
    return EMT_SUCCESS;
}

int CGeneralMsgClass::ParseMsg(void)
{
    DelFieldAll();
    if (NULL == iData)
        return EMT_ERROR;

    int iPos = 0; // 位置

    const char * bValue = GetMsgText();

    int iLength = this->GetLength();

    while (iPos < iLength) {
        SGeneralMsgStruct structPro;
        memcpy(&structPro, (void *) (bValue + iPos), sizeof(SGeneralMsgStruct));
        iPos += sizeof(SGeneralMsgStruct);

        CBaseDataField field(structPro.name);

        if (field.SetValue(bValue + iPos, structPro.length) && AddField(field))
            iPos += structPro.length;
        else
            return EMT_ERROR;
    }

    return EMT_SUCCESS;
}

