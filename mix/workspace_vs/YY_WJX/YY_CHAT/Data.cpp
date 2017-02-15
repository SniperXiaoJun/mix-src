#include "Data.h"

CData::CData(void)
{
	m_pValue = NULL;
	m_uLen = 0;
}

CData::~CData(void)
{
	delete [] m_pValue;
	m_pValue = NULL;
}
