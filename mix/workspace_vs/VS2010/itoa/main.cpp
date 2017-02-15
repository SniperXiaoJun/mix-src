#include "stdio.h"


char * itoa(int value,char * dest,int base)
{
    char * ptr = dest;
    if (NULL == ptr || base > 36) {
        return NULL;//ERROR
    }
    
    int flag = 0;
    
    if (value < 0)
    {
        flag = 1;
        value = -value;
    }
    
    do{
        int tmp = value%base;
        value = value/base;
        
        if (tmp >= 0 && tmp <= 9) {
            * ptr = '0' + tmp;
        }
        if (tmp >= 10 && tmp <= 35)
        {
            * ptr = 'A' + tmp - 10;
        }
        ptr++;
    }while (value > 0);
    
    
    if (1 == flag) {
        * ptr = '-';
    }
    else
    {
        ptr --;
    }
    
    for(char * ptrTmp = dest; ptrTmp < ptr; ptr--,ptrTmp++)
    {
        *ptrTmp = *ptrTmp^*ptr;
        *ptr = *ptrTmp^*ptr;
        *ptrTmp = *ptrTmp^*ptr;
    }
    
    return dest;
}


int main()

{
	char aa[22] = {1,2,3,4,5,6,6,7};
	printf("%s" ,itoa(3333, aa, 22));

	return 0;
}