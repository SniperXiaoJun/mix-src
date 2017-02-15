//-------------------------------------------------------------------------------------
// 修改记录: 
// 修 改 人: 陈佳康
// 修改日期: 2010-6-21
// 修改目的: 按终端组代码规范修改
//-------------------------------------------------------------------------------------
#ifndef _COMMON_H_
#define _COMMON_H_

#define EMT_SUCCESS 0x00000000
#define EMT_ERROR   0xFFFFFFFF
#define NULL    0

typedef char             Char;
typedef unsigned char    UChar;
typedef wchar_t			 WChar;

typedef bool             Bool;
#define True             true
#define False            false

typedef unsigned char    Byte;
typedef unsigned short   Word;
typedef unsigned int     Dword;
typedef unsigned __int64 Qword;

typedef char             Int8;
typedef short            Int16;
typedef int              Int32;
typedef __int64          Int64;

typedef unsigned char    UInt8;
typedef unsigned short   UInt16;
typedef unsigned int     UInt32;
typedef unsigned __int64 UInt64;

typedef long             Long;
typedef unsigned long    ULong;
typedef void*            Handle;
const Int32 SMALL_SIZE = 32;
const Int32 LARGE_SIZE = 512;
const Int32 HUGE_SIZE = 1024;
const Int32 GROUP_LEN	= 140;
const Int32 ADD_LEN_FOR_EACH_GROUP	= 40;
const Int32 MAX_SMS_GROUP_NUM = 16;
const Int32 IMSI_LENGTH = 15;
const Int32 PIN_LENGTH = 6;
const Int32 IMSI_BUF_LENGTH = 64;

#define MAXUINT32 ((UINT32)~((UINT32)0))


//32位小端
#if (defined(_MSC_VER) && defined(WINCE)) || !defined(__STRICT_ANSI__) && (defined(INTEL_CC) || (defined(_MSC_VER) && defined(WIN32)) || (defined(__GNUC__) && (defined(__DJGPP__) || defined(__CYGWIN__) || defined(__MINGW32__) || defined(__i386__))))
#define ENDIAN_LITTLE
#define ENDIAN_32BITWORD
#endif

//64位小端
#if !defined(__STRICT_ANSI__) && defined(__x86_64__) || (defined(__R5900) || defined(R5900) || defined(__R5900__)) && (defined(_mips) || defined(__mips__) || defined(mips))
#define ENDIAN_LITTLE
#define ENDIAN_64BITWORD
#endif

//PowerPC
#if !defined(__STRICT_ANSI__) && defined(LTC_PPC32)
#define ENDIAN_BIG
#define ENDIAN_32BITWORD
#endif 

//sparc和sparc64
#if defined(__sparc__)
#define ENDIAN_BIG
#if defined(__arch64__)
#define ENDIAN_64BITWORD
#else
#define ENDIAN_32BITWORD
#endif
#endif

const Byte STATE_TYPE_IDLE = 0x15;

typedef struct tagSMSMSG {
	Byte *pSMSData;
	unsigned short usSMSByteLen;
	Byte *pRecipient;
	UInt32 uRecpByteLen;
} SMSMSG, *PSMSMSG;

#endif /*COMMON_H_*/
