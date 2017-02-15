//
//typedef unsigned int u32;
//typedef unsigned short u16;
//typedef unsigned char u8;
//
//typedef struct 
//{
//    const u32 version; 
//	const char* sVersion;
//    /*---memory------*/
//    void*   (*memset)   (void *s, u8 c, u16 n); 
//    void*   (*memcpy)   (void* dest, const void* source, u16 count);
//    void*   (*memmove)  (void* dest, const void* source, u16 count);
//    u8      (*memcmp)   (const void *s1, const void *s2, u16 NumBytes);
//     /*---type  ------*/
//    u8      (*isdigit)  (u8 ch);
//    u8      (*isxdigit) (u8 ch);
//    u8      (*isalpha)  (u8 ch);
//    u8      (*islower)  (u8 ch);
//    u8      (*isupper)  (u8 ch);
//    u8      (*digitValue)   (u8 ch);
//    char    (*digittochar)  (u8 digit);
//    char    (*toupper)      (char c);
//    char    (*tolower)      (char c);
//    /*---string------*/
//    char*   (*strcpy)  (char *s1, const char* s2);
//    char*   (*strncpy) (char *s1, const char* s2, u16 n);
//    u16     (*strlen)  (const char* s); 
//    u8      (*strcmp)  (const char* s1, const char* s2); 
//    u8      (*strncmp) (const char* s1, const char* s2, u16 n);
//    char*   (*str2upper)    (char* s);
//    char*   (*str2lower)    (char* s);
//    char*   (*strchr)       (char* str, char chr);
//    char*   (*strrchr)      (char* str, char chr);
//    char*   (*strstr)       (char* str1, const char* str2);
//
//#if USE_PRINTF_LIB_100311    
//    u16     (*rand)         (u32 seed);
//    /*---printf------*/
//    int     (*vprintf)      (const char* format, va_list args, APPLIB_PRINT_ST* desc);
//    int     (*vsprintf)     (char* s, const char* format, va_list args);
//    int     (*sprintf)      (char* s, const char* format, ...);
//#endif
//}APP_SERVICE_ST;
//
//int main()
//{
//	return 0;
//}


#include <stdio.h>
#include <stdlib.h>

typedef struct a
{
  int a;
  int b;
  void (*func)(/*struct a *ptrthis, int a, int b*/);

  //static int s_i;
  //void func_static()
  //{
	 //printf("%d\n",s_i);
  //}
};
void fff(struct a *ptrToa, int x,int y)
{
	ptrToa->a = x;
	ptrToa->b = y;
}
int main(){
	struct a *aa = malloc(sizeof(struct a));
	aa->func = fff;
	aa->func(aa, 4, 5);
	printf("%d %d\n", aa->a, aa->b);
	return 0;
}