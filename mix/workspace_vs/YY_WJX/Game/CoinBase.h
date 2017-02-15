#ifndef CCOINBASE
#define CCOINBASE


#include "common.h"
#include "Base.h"

class CCoinBase:
	public CBase
{
public:
	CCoinBase(int m_J = 0, int m_G = 0, int m_S = 0, int m_C = 0);
	virtual ~CCoinBase(void);

	void FormatCoin();
	void SetMember(int m_J = 0, int m_G = 0, int m_S = 0, int m_C = 0);
	void GetMember(int *m_J, int *m_G, int *m_S, int *m_C) const;
	bool operator==(const CCoinBase& other) const;
	bool operator!=(const CCoinBase& other) const;
	bool operator>(const CCoinBase& other) const;
	bool operator>=(const CCoinBase& other) const;
	bool operator<(const CCoinBase& other) const;
	bool operator<=(const CCoinBase& other) const;
	CCoinBase& operator=(const CCoinBase& other);
	CCoinBase operator+(const CCoinBase& other) const;
	CCoinBase& operator+=(const CCoinBase& other);
	CCoinBase operator-(const CCoinBase& other) const;
	CCoinBase& operator-=(const CCoinBase& other);
	//bool operator>=(const CCoinBase& other);
	//bool operator>=(const CCoinBase& other);
	int CmpCoin(const CCoinBase& other);

	CCoinBase PCC(int num = 0) const;

private:
	int m_JewelCoin;
	int m_GoldCoin;
	int m_SilverCoin ;
	int m_Coin;
};

#endif