#include "CoinBase.h"

CCoinBase::CCoinBase(int m_J, int m_G, int m_S, int m_C)
{
	SetMember(m_J, m_G, m_S, m_C);
}

CCoinBase::~CCoinBase(void)
{

}

void CCoinBase::FormatCoin(void)
{
	int i = 0;
	
	i = m_GoldCoin / COIN_SCALE; 
	m_GoldCoin = m_GoldCoin % COIN_SCALE; 
	m_JewelCoin += i;

	i = m_SilverCoin / COIN_SCALE; 
	m_SilverCoin = m_SilverCoin % COIN_SCALE; 
	m_GoldCoin += i;

	i = m_Coin / COIN_SCALE; 
	m_Coin = m_Coin % COIN_SCALE; 
	m_SilverCoin += i;

	if(m_Coin < 0)
	{
		m_Coin += COIN_SCALE;
		m_SilverCoin--;
	}
	if(m_SilverCoin < 0)
	{
		m_SilverCoin += COIN_SCALE;
		m_GoldCoin--;
	}
	if(m_GoldCoin < 0)
	{
		m_GoldCoin += COIN_SCALE;
		m_JewelCoin--;
	}
}


int CCoinBase::CmpCoin(const CCoinBase& other)
{
	if(this->m_JewelCoin > other.m_JewelCoin)
	{
		return 1;
	}
	else if(this->m_GoldCoin > other.m_GoldCoin)
	{
		return 1;
	}
	else if(this->m_SilverCoin > other.m_SilverCoin)
	{
		return 1;
	}
	else if(this->m_Coin > other.m_Coin)
	{
		return 1;
	}
	else if(this->m_Coin == other.m_Coin)
	{
		return 0;
	}
	else 
	{
		return -1;
	}
}

void CCoinBase::SetMember(int m_J, int m_G, int m_S, int m_C)
{
	m_JewelCoin = m_J;
	m_GoldCoin = m_G;
	m_SilverCoin = m_S;
	m_Coin = m_C;

	FormatCoin();
}

void CCoinBase::GetMember(int *m_J, int *m_G, int *m_S, int *m_C) const
{
	*m_J = m_JewelCoin;
	*m_G = m_GoldCoin;
	*m_S = m_SilverCoin;
	*m_C = m_Coin;
}

bool CCoinBase::operator==(const CCoinBase& other) const
{
	if(m_JewelCoin == other.m_JewelCoin&&
		m_GoldCoin == other.m_GoldCoin&&
		m_SilverCoin == other.m_SilverCoin&&
		m_Coin == other.m_Coin)
	{
		return true;
	}
	else
	{
		return false;
	}
}


bool CCoinBase::operator!=(const CCoinBase& other) const
{
	return !(this->operator==(other));
}

bool CCoinBase::operator>(const CCoinBase& other) const
{
	if(m_JewelCoin < other.m_JewelCoin)
	{
		return false;
	}
	else if(m_GoldCoin < other.m_GoldCoin)
	{
		return false;
	}
	else if(m_SilverCoin < other.m_SilverCoin)
	{
		return false;
	}
	else if(m_Coin <= other.m_Coin)
	{
		return false;
	}
	else
	{
		return true;
	}
}

bool CCoinBase::operator>=(const CCoinBase& other) const
{ 
	if(m_JewelCoin >= other.m_JewelCoin&&
		m_GoldCoin >= other.m_GoldCoin&&
		m_SilverCoin >= other.m_SilverCoin&&
		m_Coin >= other.m_Coin)
	{
		return true;
	}
	else
	{
		return false;
	}
}

bool CCoinBase::operator<(const CCoinBase& other) const
{
	if(m_JewelCoin > other.m_JewelCoin)
	{
		return false;
	}
	else if(m_GoldCoin > other.m_GoldCoin)
	{
		return false;
	}
	else if(m_SilverCoin > other.m_SilverCoin)
	{
		return false;
	}
	else if(m_Coin >= other.m_Coin)
	{
		return false;
	}
	else
	{
		return true;
	}
}


bool CCoinBase::operator<=(const CCoinBase& other) const
{
	if(m_JewelCoin <= other.m_JewelCoin&&
		m_GoldCoin <= other.m_GoldCoin&&
		m_SilverCoin <= other.m_SilverCoin&&
		m_Coin <= other.m_Coin)
	{
		return true;
	}
	else
	{
		return false;
	}
}

CCoinBase& CCoinBase::operator=(const CCoinBase& other)
{
	m_JewelCoin = other.m_JewelCoin;
	m_GoldCoin = other.m_GoldCoin;
	m_SilverCoin = other.m_SilverCoin;
	m_Coin = other.m_Coin;

	FormatCoin();

	return *this;
}


CCoinBase CCoinBase::operator+(const CCoinBase& other) const
{
	CCoinBase temp;
	temp.m_JewelCoin = m_JewelCoin + other.m_JewelCoin;
	temp.m_GoldCoin = m_GoldCoin + other.m_GoldCoin;
	temp.m_SilverCoin = m_SilverCoin + other.m_SilverCoin;
	temp.m_Coin = m_Coin + other.m_Coin;

	temp.FormatCoin();

	return temp;
}

CCoinBase& CCoinBase::operator+=(const CCoinBase& other)
{
	m_JewelCoin += other.m_JewelCoin;
	m_GoldCoin += other.m_GoldCoin;
	m_SilverCoin += other.m_SilverCoin;
	m_Coin += other.m_Coin;

	FormatCoin();

	return *this;
}

CCoinBase CCoinBase::operator-(const CCoinBase& other) const
{
	CCoinBase temp;
	temp.m_JewelCoin = m_JewelCoin - other.m_JewelCoin;
	temp.m_GoldCoin = m_GoldCoin - other.m_GoldCoin;
	temp.m_SilverCoin = m_SilverCoin - other.m_SilverCoin;
	temp.m_Coin = m_Coin - other.m_Coin;

	temp.FormatCoin();

	return temp;
}
CCoinBase& CCoinBase::operator-=(const CCoinBase& other)
{
	m_JewelCoin -= other.m_JewelCoin;
	m_GoldCoin -= other.m_GoldCoin;
	m_SilverCoin -= other.m_SilverCoin;
	m_Coin -= other.m_Coin;

	FormatCoin();

	return *this;
}

CCoinBase CCoinBase::PCC(int num) const
{
	CCoinBase temp;

	temp.m_JewelCoin = 0;
	temp.m_GoldCoin = m_JewelCoin;
	temp.m_SilverCoin = m_GoldCoin;
	temp.m_Coin = m_SilverCoin;

	temp.m_JewelCoin *= num;
	temp.m_GoldCoin *= num;
	temp.m_SilverCoin *= num;
	temp.m_Coin *= num;

	temp.FormatCoin();
	return temp;
}
