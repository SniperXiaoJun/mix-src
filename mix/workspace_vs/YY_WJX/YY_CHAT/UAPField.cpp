/* ====================================================================
* File: UAPField.cpp
* Created: 11/11/08
* Author:	张文 
* Description : 消息字段类定义
* Version: 1.0
* Copyright (c): Taiji Lab, All rights reserved
* ==================================================================== */

#include "UAPField.h"

CUAPField::CUAPField(int iName)
{
	m_iName = iName;
    m_usValue = 0;
	m_ulValue = 0;
	m_u64Value = 0;
	m_sValue = 0;
	m_lValue = 0;
	m_szValue = '\0';
	m_i64Value = 0;
	m_btValue = 0;
	m_ulType = EUFILEDTYPE;	
}

CUAPField::CUAPField(const CUAPField &rhs)
{
	m_iName = rhs.m_iName;
	m_uLen = rhs.m_uLen;
	m_pValue = new Byte[ESTRING == rhs.m_ulType ? m_uLen + 1 : m_uLen];
	memcpy(m_pValue, rhs.m_pValue, m_uLen);
	m_ulType = rhs.m_ulType;
	
	switch (rhs.m_ulType) 
	{
	case ECHAR :
		m_szValue = rhs.m_szValue;
        break;
	case ESHORT :
		m_sValue = rhs.m_sValue;
        break;
	case ELONG :
		m_lValue = rhs.m_lValue;
        break;
	case EINT64 :
		m_i64Value = rhs.m_i64Value;
        break;
    case EBYTE:
		m_btValue = rhs.m_btValue;
        break;
    case EU16 :
		m_usValue = rhs.m_usValue;
        break;
    case EU32 :
		m_ulValue = rhs.m_ulValue;
        break;
	case EU64 :
		m_u64Value = rhs.m_u64Value;
        break;
	case ESTRING:
		m_pValue[m_uLen] = 0;
		break;
	default:
		break;
	}
}

CUAPField::~CUAPField(void)
{
}

CUAPField &CUAPField::operator = (const CUAPField &rhs)
{
	if (&rhs == this)
	{
		return *this;
	}
	
	m_iName = rhs.m_iName;
	m_uLen = rhs.m_uLen;
	delete [] m_pValue;
	m_pValue = new Byte[ESTRING == rhs.m_ulType ? m_uLen + 1 : m_uLen];
	memcpy(m_pValue, rhs.m_pValue, m_uLen);
	m_ulType = rhs.m_ulType;
	
	switch (rhs.m_ulType) 
	{
	case ECHAR :
		m_szValue = rhs.m_szValue;
        break;
	case ESHORT :
		m_sValue = rhs.m_sValue;
        break;
	case ELONG :
		m_lValue = rhs.m_lValue;
        break;
	case EINT64 :
		m_i64Value = rhs.m_i64Value;
        break;
	case EBYTE:
		m_btValue = rhs.m_btValue;
        break;
    case EU16 :
		m_usValue = rhs.m_usValue;
        break;
    case EU32 :
		m_ulValue = rhs.m_ulValue;
        break;
	case EU64 :
		m_u64Value = rhs.m_u64Value;
        break;
	default:
		break;
	}
	
	return *this;
}

CUAPField &CUAPField::operator = (char szValue)
{
	SetValue(szValue);	
	return *this;
}

CUAPField &CUAPField::operator = (short sValue)
{
	SetValue(sValue);
	return *this;
}

CUAPField &CUAPField::operator = (long lValue)
{
	SetValue(lValue);
	return *this;
}

CUAPField &CUAPField::operator = (__int64 i64Value)
{
	SetValue(i64Value);
	return *this;
}

CUAPField &CUAPField::operator = (Byte btValue)
{
	SetValue(btValue);
	return *this;
}

CUAPField &CUAPField::operator = (UInt16 usValue)
{
	SetValue(usValue);
	return *this;
}

CUAPField &CUAPField::operator = (UInt32 ulValue)
{
	SetValue(ulValue);
	return *this;
}

CUAPField &CUAPField::operator = (UInt64 u64Value)
{
	SetValue(u64Value);
	return *this;
}

CUAPField &CUAPField::operator = (const char *pString)
{
	SetValue(pString);
	return *this;
}

CUAPField &CUAPField::operator = (const string &strValue)
{
	SetValue(strValue);
	return *this;
}

bool CUAPField::SetValue(const Byte *pValue, UInt32 ulLen, UInt32 ulType)
{
	m_ulType = ulType;
	if (ESTRING > m_ulType)
	{
		Byte *pTemp = NULL;
		pTemp = new Byte[ulLen];
		for (UInt32 i = 0; i < ulLen; i++)
		{
			pTemp[i] = pValue[ulLen - 1 - i];
		}

		switch (m_ulType) 
		{
		case ECHAR :
			m_szValue = *(char *)pTemp;
			break;
		case ESHORT :
			m_sValue = *(short *)pTemp;
			break;
		case ELONG :
			m_lValue = *(long *)pTemp;
			break;
		case EINT64 :
			m_i64Value = *(__int64 *)pTemp;
			break;
		case EBYTE:
			m_btValue = *pTemp;
			break;
		case EU16 :
			m_usValue = *(UInt16 *)pTemp;
			break;
		case EU32 :
			m_ulValue = *(UInt32 *)pTemp;
			break;
		case EU64 :
			m_u64Value = *(UInt64 *)pTemp;
			break;
		default:
			break;
		}

		delete [] pTemp;
		pTemp = NULL;
	}

	m_uLen = ulLen;
	
	delete [] m_pValue;
	if (ESTRING == m_ulType)
	{
		m_pValue = new Byte[m_uLen + 1];
		m_pValue[m_uLen] = 0;
	}
	else
	{
		m_pValue = new Byte[m_uLen];
	}
	
	memcpy(m_pValue, pValue, m_uLen);
	return true;
}

bool CUAPField::SetValue(const char *pString)
{
	return SetValue((const Byte *)pString, strlen(pString), ESTRING);
}

bool CUAPField::SetValue(const string &strValue)
{
	return SetValue((const Byte *)strValue.c_str(), strValue.length(), ESTRING);
}

bool CUAPField::SetValue(char szValue)
{
	m_ulType = ECHAR;
	m_szValue = szValue;
	
	return SetBEValue((Byte *)&szValue, sizeof(char));
}

bool CUAPField::SetValue(short sValue)
{
	m_ulType = ESHORT;
	m_sValue = sValue;
	
	return SetBEValue((Byte *)&sValue, sizeof(short));
}

bool CUAPField::SetValue(long lValue)
{
	m_ulType = ELONG;
	m_lValue = lValue;
	
	return SetBEValue((Byte *)&lValue, sizeof(long));
}

bool CUAPField::SetValue(__int64 i64Value)
{
	m_ulType = EINT64;
	m_i64Value = i64Value;
	
	return SetBEValue((Byte *)&i64Value, sizeof(__int64));
}

bool CUAPField::SetValue(Byte btValue)
{
	m_ulType = EBYTE;
	m_btValue = btValue;
	
	return SetBEValue(&btValue, sizeof(Byte));
}

bool CUAPField::SetValue(UInt16 usValue)
{
	m_ulType = EU16;
	m_usValue = usValue;
	
	return SetBEValue((Byte *)&usValue, sizeof(UInt16));
}

bool CUAPField::SetValue(UInt32 ulValue)
{
	m_ulType = EU32;
	m_ulValue = ulValue;
	
	return SetBEValue((Byte *)&ulValue, sizeof(UInt32));
}

bool CUAPField::SetValue(UInt64 u64Value)
{
	m_ulType = EU64;
	m_u64Value = u64Value;
	
	return SetBEValue((Byte *)&u64Value, sizeof(UInt64));
}

inline bool CUAPField::SetName(int iName)
{
	m_iName = iName;
	
	return true;
}

const Byte *CUAPField::GetValue(void) const
{
	return m_pValue;
}

const char *CUAPField::GetValueString(void) const
{
	if (ESTRING == m_ulType)
	{
		return (const char *)m_pValue;
	} 
	else
	{
		throw CUAPException(CUAPException::EFIELD_TYPE_ERROR);
	}
}

char CUAPField::GetValueChar(void) const
{
	if (ECHAR == m_ulType)
	{
		return m_szValue;
	}
	else
	{
		throw CUAPException(CUAPException::EFIELD_TYPE_ERROR);
	}
}

short CUAPField::GetValueShort(void) const
{
	if (ESHORT == m_ulType)
	{
		return m_sValue;
	}
	else
	{
		throw CUAPException(CUAPException::EFIELD_TYPE_ERROR);
	}
}

long CUAPField::GetValueLong(void) const
{
	if (ELONG == m_ulType)
	{
		return m_lValue;
	}
	else
	{
		throw CUAPException(CUAPException::EFIELD_TYPE_ERROR);
	}
}

__int64 CUAPField::GetValueI64(void) const
{
	if (EINT64 == m_ulType)
	{
		return m_i64Value;
	}
	else
	{
		throw CUAPException(CUAPException::EFIELD_TYPE_ERROR);
	}
}

Byte CUAPField::GetValueByte(void) const
{
	if (EBYTE == m_ulType)
	{
		return m_btValue;
	}
	else
	{
		throw CUAPException(CUAPException::EFIELD_TYPE_ERROR);
	}
}

UInt16 CUAPField::GetValueU16(void) const
{
	if (EU16 == m_ulType)
	{
		return m_usValue;
	}
	else
	{
		throw CUAPException(CUAPException::EFIELD_TYPE_ERROR);
	}
}

UInt32 CUAPField::GetValueU32(void) const
{
	if (EU32 == m_ulType)
	{
		return m_ulValue;
	}
	else
	{
		throw CUAPException(CUAPException::EFIELD_TYPE_ERROR);
	}
}

UInt64 CUAPField::GetValueU64(void) const
{
	if (EU64 == m_ulType)
	{
		return m_u64Value;
	}
	else
	{
		throw CUAPException(CUAPException::EFIELD_TYPE_ERROR);
	}
}

inline UInt32 CUAPField::GetLength(void) const
{
	return m_uLen;
}

inline int CUAPField::GetName(void) const
{
	return m_iName;
}

inline UInt32 CUAPField::GetType(void) const
{
	return m_ulType;
}

bool CUAPField::SetBEValue(const Byte *pValue, UInt32 ulLen)
{
	m_uLen = ulLen;
	
	delete [] m_pValue;	
	m_pValue = new Byte[m_uLen];

	for (UInt32 i = 0; i < m_uLen; i++)
	{
		m_pValue[i] = pValue[m_uLen - 1 - i];
	}
	
	return true;
}
