#include "ExperBase.h"

CExperBase::CExperBase(int m_J, int m_G, int m_S, int m_C)
{
	SetMember(m_J, m_G, m_S, m_C);
}

CExperBase::~CExperBase(void)
{

}

void CExperBase::FormatExper(void)
{
	int i = 0;
	
	i = m_GoldExper / EXPER_SCALE; 
	m_GoldExper = m_GoldExper % EXPER_SCALE; 
	m_JewelExper += i;

	i = m_SilverExper / EXPER_SCALE; 
	m_SilverExper = m_SilverExper % EXPER_SCALE; 
	m_GoldExper += i;

	i = m_Exper / EXPER_SCALE; 
	m_Exper = m_Exper % EXPER_SCALE; 
	m_SilverExper += i;

	if(m_Exper < 0)
	{
		m_Exper += EXPER_SCALE;
		m_SilverExper--;
	}
	if(m_SilverExper < 0)
	{
		m_SilverExper += EXPER_SCALE;
		m_GoldExper--;
	}
	if(m_GoldExper < 0)
	{
		m_GoldExper += EXPER_SCALE;
		m_JewelExper--;
	}
}


int CExperBase::CmpExper(const CExperBase& other)
{
	if(this->m_JewelExper > other.m_JewelExper)
	{
		return 1;
	}
	else if(this->m_GoldExper > other.m_GoldExper)
	{
		return 1;
	}
	else if(this->m_SilverExper > other.m_SilverExper)
	{
		return 1;
	}
	else if(this->m_Exper > other.m_Exper)
	{
		return 1;
	}
	else if(this->m_Exper == other.m_Exper)
	{
		return 0;
	}
	else 
	{
		return -1;
	}
}

void CExperBase::SetMember(int m_J, int m_G, int m_S, int m_C)
{
	m_JewelExper = m_J;
	m_GoldExper = m_G;
	m_SilverExper = m_S;
	m_Exper = m_C;

	FormatExper();
}

void CExperBase::GetMember(int *m_J, int *m_G, int *m_S, int *m_C) const
{
	*m_J = m_JewelExper;
	*m_G = m_GoldExper;
	*m_S = m_SilverExper;
	*m_C = m_Exper;
}

bool CExperBase::operator==(const CExperBase& other) const
{
	if(m_JewelExper == other.m_JewelExper&&
		m_GoldExper == other.m_GoldExper&&
		m_SilverExper == other.m_SilverExper&&
		m_Exper == other.m_Exper)
	{
		return true;
	}
	else
	{
		return false;
	}
}


bool CExperBase::operator!=(const CExperBase& other) const
{
	return !(this->operator==(other));
}

bool CExperBase::operator>(const CExperBase& other) const
{
	if(m_JewelExper < other.m_JewelExper)
	{
		return false;
	}
	else if(m_GoldExper < other.m_GoldExper)
	{
		return false;
	}
	else if(m_SilverExper < other.m_SilverExper)
	{
		return false;
	}
	else if(m_Exper <= other.m_Exper)
	{
		return false;
	}
	else
	{
		return true;
	}
}

bool CExperBase::operator>=(const CExperBase& other) const
{ 
	if(m_JewelExper >= other.m_JewelExper&&
		m_GoldExper >= other.m_GoldExper&&
		m_SilverExper >= other.m_SilverExper&&
		m_Exper >= other.m_Exper)
	{
		return true;
	}
	else
	{
		return false;
	}
}

bool CExperBase::operator<(const CExperBase& other) const
{
	if(m_JewelExper > other.m_JewelExper)
	{
		return false;
	}
	else if(m_GoldExper > other.m_GoldExper)
	{
		return false;
	}
	else if(m_SilverExper > other.m_SilverExper)
	{
		return false;
	}
	else if(m_Exper >= other.m_Exper)
	{
		return false;
	}
	else
	{
		return true;
	}
}


bool CExperBase::operator<=(const CExperBase& other) const
{
	if(m_JewelExper <= other.m_JewelExper&&
		m_GoldExper <= other.m_GoldExper&&
		m_SilverExper <= other.m_SilverExper&&
		m_Exper <= other.m_Exper)
	{
		return true;
	}
	else
	{
		return false;
	}
}

CExperBase& CExperBase::operator=(const CExperBase& other)
{
	m_JewelExper = other.m_JewelExper;
	m_GoldExper = other.m_GoldExper;
	m_SilverExper = other.m_SilverExper;
	m_Exper = other.m_Exper;

	FormatExper();

	return *this;
}


CExperBase CExperBase::operator+(const CExperBase& other) const
{
	CExperBase temp;
	temp.m_JewelExper = m_JewelExper + other.m_JewelExper;
	temp.m_GoldExper = m_GoldExper + other.m_GoldExper;
	temp.m_SilverExper = m_SilverExper + other.m_SilverExper;
	temp.m_Exper = m_Exper + other.m_Exper;

	temp.FormatExper();

	return temp;
}

CExperBase& CExperBase::operator+=(const CExperBase& other)
{
	m_JewelExper += other.m_JewelExper;
	m_GoldExper += other.m_GoldExper;
	m_SilverExper += other.m_SilverExper;
	m_Exper += other.m_Exper;

	FormatExper();

	return *this;
}

CExperBase CExperBase::operator-(const CExperBase& other) const
{
	CExperBase temp;
	temp.m_JewelExper = m_JewelExper - other.m_JewelExper;
	temp.m_GoldExper = m_GoldExper - other.m_GoldExper;
	temp.m_SilverExper = m_SilverExper - other.m_SilverExper;
	temp.m_Exper = m_Exper - other.m_Exper;

	temp.FormatExper();

	return temp;
}
CExperBase& CExperBase::operator-=(const CExperBase& other)
{
	m_JewelExper -= other.m_JewelExper;
	m_GoldExper -= other.m_GoldExper;
	m_SilverExper -= other.m_SilverExper;
	m_Exper -= other.m_Exper;

	FormatExper();

	return *this;
}

