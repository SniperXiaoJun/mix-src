// TestForSKill.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"


int func_cal(int base, int num_true, int num_guess,int times)
{
	int i = 0;
	int add = base;
	for (; i < times; i++)
	{
		add = (add + 1)/2;
	}

	printf("次数%d，猜：%d\n",times, num_guess);
	if (num_true == num_guess)
	{
		
	}
	else if (num_guess < num_true)
	{
		num_guess += add;

		return func_cal(base, num_true, num_guess, times + 1);
	}
	else
	{
		num_guess -= add;

		return func_cal(base, num_true, num_guess, times + 1);
	}
}


int func_cal_512(int base, int num_true, int num_guess,int times)
{
	int i = 0;
	int add = base;
	for (; i < times; i++)
	{
		add = (add + 1)/2;
	}

	printf("次数%d，猜：%d\n",times, num_guess);
	if (num_true == num_guess)
	{

	}
	else if (num_guess < num_true)
	{
		num_guess += add;

		return func_cal(base, num_true, num_guess, times + 1);
	}
	else
	{
		num_guess -= add;

		return func_cal(base, num_true, num_guess, times + 1);
	}
}


int _tmain(int argc, _TCHAR* argv[])
{
	int i=0;

	int base = 512;

	for (i = 0; i < base;i++)
	{
		printf("固定值是：%d\n", i+1);
		//printf("固定值是算法1\n");
		//func_cal(base, i+1, base, 1);
		printf("固定值是算法2\n");
		func_cal_512(base/2 ,i+1, base/2,1);
	}

	return 0;
}

