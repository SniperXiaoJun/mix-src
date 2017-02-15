
#include <stdio.h>

char * my_itoa(unsigned int num, unsigned int base, char * dest)
{
	int i = 0;
	int left = 0;

	if(base < 2 || base > 36)
	{
		return NULL;
	}

	do
	{
		if(num%base > 10)
		{
			*(dest + i) = num%base + 'A' - 10;
		}
		else
		{
			*(dest + i) = num%base + '0';
		}
		num = num / base;
		i++;
		
	}while(num);

	* (dest + i) = '\0';

	i--;

	

	while(left < i)
	{
		*(dest + i) = *(dest + i) ^ *(dest + left);
		*(dest + left) = *(dest + i) ^ *(dest + left);
		*(dest + i) = *(dest + i) ^ *(dest + left);
		left++;
		i--;
	}

	return dest;
}

unsigned int my_atoi(const char * str_src,unsigned int base)
{
	int num = 0;

	if(base > 36 || base < 2)
	{
		return 0;
	}

	for(;*str_src;str_src++)
	{
		if( * str_src >= 'A'  && * str_src <= 'Z')
		{
			num = num * base + *str_src - 'A' + 10;
		}
		else if( * str_src >= 'a'  && * str_src <= 'z')
		{
			num = num * base + *str_src - 'a' + 10;
		}
		else
		{
			num = num * base + *str_src - '0';
		}
	}

	return num;
}

struct sa
{
	char * p, q;
	union
	{
		short a,b;
		char c;
	} a;
	struct sa * next;
};


struct s1
{
unsigned int i: 8;
unsigned int j: 3;
unsigned int a: 4;
//double b;
};

int main(int argc, char * argv[])
{
	unsigned int aaa = my_atoi("zz", 36);

	int jj = sizeof(struct s1);
	char p[10] = {1,2,3,4};

	int k;

	void * pp;

	struct s1  * s;

	jj = sizeof(s);

	s = 0x0;

	k = s + 1;
	k = (char *)s + 1;

	pp = &s;

	//void (*x(int (*y)(int z, int t)))();

	

	printf("%s\n", my_itoa( 9, 16 ,p));
	
	return aaa;
}