//*****************************************************************************
//
//	GLOBALS.H
//	Version 2.0
//
//	CLAIM:
//	This sample code is used for the purpose of the
//	company's internal training and guidance only. DigiCrypto will not
//	be responsible for the use of this code for any purpose other than
//	what described above.
//
//*****************************************************************************
//
//	Purpose:
//	This sample 'header filecode defines the global variables used for the
//	sample code work space.
//
//	The definition "_TEST_" can be set to re-direct the error output to a file
//	rather than standard output (i.e. DOS window). This feature is particular
//	usefull if you want to write a batch file to quickly test all projects. If
//	you don't want to use this feature, then comment out the line 31.
//	for example, subtitute the line 31 with: //#define _TEST_
//
//*****************************************************************************

#ifndef ___GLOBALS_DOT_H___
#define ___GLOBALS_DOT_H___

//*************************************************************************
//define this to re-direct the output to a file rather than standard output
#define _TEST_

//*************************************************************************

#ifdef _TEST_
#define STDERR fout
#else
#define STDERR stderr
#endif

#ifdef _TEST_

#ifdef WIN32
#include <windows.h>
#else
#include <stdio.h>
#include <stdlib.h>
#endif

// Detect Linux(including Android).
#if defined(linux) || defined(__linux__)	// Linux
#define _LINUX_OS_DEF
#endif // end: #if defined(linux) || defined(__linux__)	// Linux

FILE * fout;

#ifdef WIN32
SYSTEMTIME st;
#define TESTINITIALIZE	fout = fopen (".\\TestResult.txt", "a+"); \
						fprintf (STDERR, "========================================================\n"); \
						fprintf (STDERR, "\n\nProject Name: %s - Date: %d/%d/%d - Time: %02dh%02dm\n",  \
									ProjName, st.wMonth, st.wDay, st.wYear, st.wHour, st.wMinute)
#elif defined(_ANDROID_PLATFORM_) 
#define TESTINITIALIZE	fout = fopen ("/data/local/bin/TestResult.txt", "a+"); \
						fprintf (STDERR, "========================================================\n"); \
						fprintf (STDERR, "\n\nProject Name: %s\n", ProjName);
#elif defined(_LINUX_OS_DEF) //linux
#define TESTINITIALIZE	fout = fopen("./TestResult.txt", "a+"); \
						fprintf (STDERR, "========================================================\n"); \
						fprintf (STDERR, "\n\nProject Name: %s\n", ProjName);
#else	
#define TESTINITIALIZE	printf("Unkonw system\n"); \
						exit(0);
#endif		//WIN32
						
#define TESTFINALIZE fclose (fout)

#else
#define TESTINITIALIZE
#define TESTFINALIZE
#endif

char * SOpin = "12345678";
char * userPin = "88888888";

#endif
