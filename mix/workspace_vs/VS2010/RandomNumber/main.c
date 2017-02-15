#include <stdio.h>
#include <time.h>
#include <stdlib.h>
int main(void)
{
 int a[100],i,j,t,x;

 srand(time(NULL));
 for(i=0;i<=99;i++) 
 {
	 a[i]=rand();
 }
 for(i=0;i<=99;i++)
 {
	 printf("%10d\t",a[i]);
 }
 getch();
 return 0;
}