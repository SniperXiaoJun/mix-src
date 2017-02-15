/*
 * MSArg.cpp
 *
 *  Created on: 2011-6-10
 *      Author: Ice Lee
 */

#include "Arg.h"

//06 
CArg::CArg()
{
	m_iType = -1;
	m_iCode = -1;
	for (int i=0; i < ARG_NUM; i++)
	{
	m_pPointer[i] = NULL;
	m_uiLength[i] = 0;
	}
}

CArg::~CArg()
	{
	m_iType = -1;
	m_iCode = -1;
	for (Int32 i = 0; i < ARG_NUM; i++)
		{
		m_pPointer[i] = NULL;
		m_uiLength[i] = 0;
		}
	}

Int32 CArg::SetType(Int32 iType)
	{
	m_iType = iType;
	return 0;
	}

Int32 CArg::GetType()
	{
	return m_iType;
	}

Int32 CArg::SetCode(Int32 iCode)
	{
	m_iCode = iCode;
	return 0;
	}

Int32 CArg::GetCode()
	{
	return m_iCode;
	}
Int32 CArg::SetIndex(Int32 iIndex)
	{
	m_iIndex = iIndex;
	return 0;
	}

Int32 CArg::GetIndex()
	{
	return m_iIndex;
	}

Int32 CArg::SetPointer(Int32 iNum, void* pPointer)
	{
	if(iNum > ARG_NUM)
		return -1;
	m_pPointer[iNum-1] = pPointer;
	return 0;
	}

void* CArg::GetPointer(Int32 iNum)
	{
	if(iNum > ARG_NUM)
		return NULL;
	return m_pPointer[iNum-1];
	}
		
Int32 CArg::SetLength(Int32 iNum, Int32 iLen)
	{
	if (iNum > ARG_NUM)
		return -1;
	m_uiLength[iNum - 1] = iLen;
	return 0;
	}

Int32 CArg::GetLength(Int32 iNum)
	{
	if (iNum > ARG_NUM)
		return -1;
	return m_uiLength[iNum - 1];
	}
