#pragma once

#include "YY_Base.h"

class YY_BaseBall :
	public YY_Base
{
public:
	YY_BaseBall(int iRadiusSelf = 1, int iRadiusRound = 0, int iAnglesSelf = 1, int iAnglesRound = 0);
	virtual ~YY_BaseBall(void);

	void SetBaseBall(int iRadiusSelf = 1, int iRadiusRound = 1, int iAnglesSelf = 0, int iAnglesRound = 0);
	int GetRadiusSelf();
	int GetRadiusRound();
	int GetAnglesSelf();
	int GetAnglesRound();

	void DrawBaseBall();

protected:
	int iRadiusSelf;
	int iRadiusRound;
	int iAnglesSelf;
	int iAnglesRound;
};
