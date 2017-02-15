#ifndef CEXPERBASE_H
#define CEXPERBASE_H

#include "common.h"
#include "Base.h"

class CExperBase
	:public CBase
{
public:
	CExperBase(int m_J = 0, int m_G = 0, int m_S = 0, int m_C = 0);
	virtual ~CExperBase(void);

	void FormatExper();
	void SetMember(int m_J = 0, int m_G = 0, int m_S = 0, int m_C = 0);
	void GetMember(int *m_J, int *m_G, int *m_S, int *m_C) const;
	bool operator==(const CExperBase& other) const;
	bool operator!=(const CExperBase& other) const;
	bool operator>(const CExperBase& other) const;
	bool operator>=(const CExperBase& other) const;
	bool operator<(const CExperBase& other) const;
	bool operator<=(const CExperBase& other) const;
	CExperBase& operator=(const CExperBase& other);
	CExperBase operator+(const CExperBase& other) const;
	CExperBase& operator+=(const CExperBase& other);
	CExperBase operator-(const CExperBase& other) const;
	CExperBase& operator-=(const CExperBase& other);
	//bool operator>=(const CExperBase& other);
	//bool operator>=(const CExperBase& other);
	int CmpExper(const CExperBase& other);

private:
	int m_JewelExper;
	int m_GoldExper;
	int m_SilverExper;
	int m_Exper;
};

#endif