/* ====================================================================
* File: UAPMsg.cpp
* Created: 11/11/08
* Author:	张文 
* Description : 消息类定义
* Version: 1.0
* Copyright (c): Taiji Lab, All rights reserved
* ==================================================================== */

#include "UAPMsg.h"

#include <STDIO.H>


CUAPMsg::CUAPMsg(int iName) : CUAPField(iName)
{
	m_ulFieldPos = 0;
}

CUAPMsg::CUAPMsg(const Byte *pValue, UInt32 ulLen, int iName) : CUAPField(iName)
{
	m_uLen = ulLen;
	m_pValue = new Byte [m_uLen];
	memcpy(m_pValue, pValue, m_uLen);
	m_ulFieldPos = 0;
}

CUAPMsg::CUAPMsg(const CUAPMsg &rhs)
: CUAPField(rhs.m_iName), m_mapNameNum(rhs.m_mapNameNum), m_mapNamePos(rhs.m_mapNamePos)
{
	m_uLen = rhs.m_uLen;
	m_pValue = new Byte [m_uLen];
	memcpy(m_pValue, rhs.m_pValue, m_uLen);
	m_ulFieldPos = rhs.m_ulFieldPos;

	for (UInt32 i = 0; i < rhs.m_vecMsgEntity.size(); i++)
	{
		m_vecMsgEntity.push_back(new CUAPField(*rhs.m_vecMsgEntity[i]));
	}
}

CUAPMsg::~CUAPMsg(void)
{
	for (UInt32 i = 0; i < m_vecMsgEntity.size(); i++)
	{
		delete m_vecMsgEntity[i];
		m_vecMsgEntity[i] = NULL;
	}
	
	m_vecMsgEntity.clear();
}

bool CUAPMsg::AddField(const CUAPField &field)
{
	CUAPField *pFld = CreateField(field);
	m_vecMsgEntity.push_back(pFld);
	
	UInt32 ulFieldCount = (0 == m_mapNameNum.count(field.GetName())) ? 0
		: m_mapNameNum[field.GetName()];
	char szFieldCount[100];
	sprintf(szFieldCount, "%d %d", field.GetName(), ulFieldCount);
	
	m_mapNamePos[szFieldCount] = m_ulFieldPos++;
	m_mapNameNum[field.GetName()] = ulFieldCount + 1;
	
	return true;
}

UInt32 CUAPMsg::GetFieldNumber(void) const
{
	return m_vecMsgEntity.size();
}

UInt32 CUAPMsg::GetFieldNumber(int iName) const
{
	return ((map<int, UInt32>)m_mapNameNum)[iName]; //在常成员函数中map的下标访问需要指明模板类型
}

const CUAPField &CUAPMsg::operator [] (UInt32 ulNum) const
{
	if (ulNum > m_vecMsgEntity.size())
	{
		throw CUAPException(CUAPException::EACCESS_VIOLATION);
	}
	
	return *m_vecMsgEntity[ulNum];
}

bool CUAPMsg::CheckField(int iName)
{
	if (0 == m_mapNameNum.count(iName) || 0 == m_mapNameNum[iName])
	{
		return false;
	}
	else
	{
		return true;
	}
}

const CUAPField &CUAPMsg::GetField(int iName, UInt32 ulPos) const
{
	if (0 == m_mapNameNum.count(iName)
		|| ulPos >= ((map<int, UInt32>)m_mapNameNum)[iName])
	{
		throw CUAPException(CUAPException::EFIELD_ERROR);
	}
	
	char szPos[100];
	sprintf(szPos, "%d %d", iName, ulPos);
	
	return *m_vecMsgEntity[((map<string, UInt32>)m_mapNamePos)[szPos]];
}

bool CUAPMsg::DelField(int iName, UInt32 ulPos)
{
	if (0 == m_mapNameNum.count(iName) || ulPos >= m_mapNameNum[iName])
	{
		return false;
	}
	
	char szPosPre[100], szPosNext[100];
	for (; ulPos < m_mapNameNum[iName] - 1; ulPos++)
	{
		sprintf(szPosPre, "%d %d", iName, ulPos);
		sprintf(szPosNext, "%d %d", iName, ulPos + 1);
		
		m_mapNamePos[szPosPre] = m_mapNamePos[szPosNext];
	}
	
	m_mapNameNum[iName]--;
	
	return true;
}

bool CUAPMsg::DelFieldAll()
{
	m_vecMsgEntity.clear();

	m_ulFieldPos = 0;
	m_mapNamePos.clear();
	m_mapNameNum.clear();

	return true;
}

bool CUAPMsg::ModField(const CUAPField &field, UInt32 ulPos)
{
	if (0 == m_mapNameNum.count(field.GetName()) || ulPos >= m_mapNameNum[field.GetName()])
	{
		return false;
	}
	
	char szPos[100];
	sprintf(szPos, "%d %d", field.GetName(), ulPos);
	m_vecMsgEntity[m_mapNamePos[szPos]]->SetValue(field.GetValue(),
		field.GetLength(), field.GetType());
	
	return true;
}

const Byte *CUAPMsg::GetMsgText(void) const
{
	return m_pValue;
}

UInt32 CUAPMsg::GetMsgLen(void) const
{
	return m_uLen;
}

CUAPField *CUAPMsg::CreateField(const CUAPField &field)
{
	return new CUAPField(field);
}
