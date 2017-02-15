/*
 * CBankMsg.cpp
 *
 *  Created on: 2011-9-26
 *      Author: Administrator
 */

#include "CGeneralMsgClass.h"

CGeneralMsgClass::CGeneralMsgClass(const Byte *pValue, UInt32 ulLen) :
    CUAPMsg(pValue, ulLen)
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

    m_uLen = 0;

    for (int iName = 0; iName < EFIELD_NAME_USR_COUNT; iName++) {
        iLength = GetFieldNumber(iName);
        for (iPos = 0; iPos < iLength; iPos++) {
            m_uLen += sizeof(SGeneralMsgStruct);
            m_uLen += GetField(iName, iPos).GetLength();
        }
    }

    delete[] m_pValue;
    m_pValue = new Byte[m_uLen];
    m_uLen = 0;

    for (int iName = 0; iName < EFIELD_NAME_USR_COUNT; iName++) {
        iLength = GetFieldNumber(iName);
        for (iPos = 0; iPos < iLength; iPos++) {
            CUAPField fieldPro(USR_NAME);
            SGeneralMsgStruct structPro;
            const CUAPField &field = GetField(iName, iPos);

            structPro.length = field.GetLength();
            structPro.name = field.GetName();
            fieldPro.SetValue((Byte *) (&structPro), sizeof(SGeneralMsgStruct));

            memcpy(m_pValue + m_uLen, fieldPro.GetValue(), fieldPro.GetLength());
            m_uLen += fieldPro.GetLength();

            memcpy(m_pValue + m_uLen, field.GetValue(), field.GetLength());
            m_uLen += field.GetLength();
        }
    }
    return EMT_SUCCESS;
}

int CGeneralMsgClass::ParseMsg(void)
{
    DelFieldAll();
    if (NULL == m_pValue)
        return EMT_ERROR;

    int iPos = 0; // 位置

    const Byte * bValue = GetMsgText();

    int iLength = this->GetLength();

    while (iPos < iLength) {
        SGeneralMsgStruct structPro;
        memcpy(&structPro, (void *) (bValue + iPos), sizeof(SGeneralMsgStruct));
        iPos += sizeof(SGeneralMsgStruct);

        CUAPField field(structPro.name);

        if (field.SetValue(bValue + iPos, structPro.length) && AddField(field))
            iPos += structPro.length;
        else
            return EMT_ERROR;
    }

    return EMT_SUCCESS;
}

