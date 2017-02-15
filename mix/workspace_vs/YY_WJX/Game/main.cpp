#include <iostream>
#include <stdio.h>

#include "AttrBase.h"
#include "UserBase.h"
#include "CoinBase.h"

using namespace std;

int main(int argc,char * argv)
{
	CAttrBase attr;
	CUserBase user;
	CCoinBase coin(1,2,3,4);

	//attr.SetElement(9,100);
	//int value = attr.GetElement(9);

	//attr.ShowAllElement();

	int i,j,k,l;

	i = j = k = l = 1;

	//if(coin > CCoinBase(1,2,3,3))
	//{
	//	printf("222");
	//}
	//else
	//{
	//	return 0;
	//}
	coin += coin;
	coin = coin.PCC(9900);

	coin.GetMember(&i,&j,&k,&l);




	//printf("%d\n%d\n%d\n%d\n",i,j,k,l);
	
	printf("Your Money is %4d,%4d,%4d,%4d$",i,j,k,l);

	return getchar();
}