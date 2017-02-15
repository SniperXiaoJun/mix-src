#include "Link.h"
#include <stdio.h>

CLink::CLink()
{
	m_iTotal = 0;
	m_pCurrent = 0;
	m_pHead = 0;
	m_pTail = 0;
}

CLink::~CLink(void)
{

}

sNode * CLink::At(int pos)
{
	return NULL;
}

sNode * CLink::Next()
{
	return NULL;
}

sNode * CLink::Previous()
{
	return NULL;
}

int CLink::TotalNumber()
{
	return 0;
}
int CLink::Add(sNode * node)
{
	return 0;
}

int CLink::Del(sNode * node)
{
	return 0;
}
int CLink::Del(int pos)
{
	return 0;
}

int CLink::Update(sNode * from, sNode * to)
{
	return 0;
}
int CLink::Update(int pos, sNode * to)
{
	return 0;
}

sNode * CLink::Select(sNode * value)
{
	return 0;
}