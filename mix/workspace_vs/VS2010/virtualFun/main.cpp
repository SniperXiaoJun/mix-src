#include <stdio.h>

class Base
{
	char a;
};

class Base2nd:public Base
{
	//virtual void fun(){ }
	void fun1(){}
};

class Base3rd:public Base2nd
{
	virtual void fun(){ }
	void fun2(){}
};




int main(int argc, char * argv[])
{
	int AA = sizeof(Base);

	AA = sizeof(Base2nd);

	AA = sizeof(Base3rd);

	return 0;
}