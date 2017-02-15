
#include "stdafx.h"
#include "YY_BaseBall.h"

YY_BaseBall::YY_BaseBall(int iRadiusSelf, int iRadiusRound, int iAnglesSelf, int iAnglesRound)
{
	SetBaseBall(iRadiusSelf,   iRadiusRound,  iAnglesSelf, iAnglesRound);
}

YY_BaseBall::~YY_BaseBall(void)
{

}

void YY_BaseBall::SetBaseBall(int iRadiusSelf, int iRadiusRound, int iAnglesSelf, int iAnglesRound)
{
	this->iAnglesRound = iAnglesRound;
	this->iAnglesSelf = iAnglesSelf;
	this->iRadiusRound = iRadiusRound;
	this->iRadiusSelf = iRadiusSelf;
}

int YY_BaseBall::GetRadiusSelf()
{
	return iRadiusSelf;
}

int YY_BaseBall::GetRadiusRound()
{
	return iRadiusRound;
}

int YY_BaseBall::GetAnglesSelf()
{
	return iAnglesSelf;
}

int YY_BaseBall::GetAnglesRound()
{
	return iAnglesRound;
}

void YY_BaseBall::DrawBaseBall()
{
	auxSolidSphere(2);
}
