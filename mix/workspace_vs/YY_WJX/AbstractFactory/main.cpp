
//#include "AbstractFactory.h"
//
//#include <iostream> 
//
//using namespace std;
//
//int main(int argc,char* argv[]) 
//{ 
//	AbstractFactory* cf1 = new ConcreteFactory1();
//	cf1->CreateProductA();
//	cf1->CreateProductB();
//	AbstractFactory* cf2 = new ConcreteFactory2(); 
//	cf2->CreateProductA(); 
//	cf2->CreateProductB();
//
//	
//	return getchar(); 
//}


#include <stdio.h>

int main()
{
	int a[5] = {1,2,3,4,5};

	int *ptr1 = (int *)(&a +1);
	int *ptr2 = (int *)((int)a + 1);

	printf("%x,%x\n",a,ptr1);
	printf("%x,%x\n",a,ptr2);
	printf("%x,%x", ptr1[-1], *ptr2);
	return getchar();
}