

#ifndef __COMMON_H__

#define __COMMON_H__

// export
#ifdef _WINDOWS
#ifdef DLL_EXPORTS
#define COMMON_API __declspec(dllexport)
#else
#define COMMON_API 
#endif
#else
#define COMMON_API 
#endif

// debug
#ifdef _DEBUG
#define DEBUG(format,...) printf("File: "__FILE__", Line: %05d: "format"\n", __LINE__, ##__VA_ARGS__);
#else
#define DEBUG(format,...)
#endif

#define BUFFER_LEN_1K 1024
#define SIZE_1K 1024
#define COUNT_1K 1024

#endif
