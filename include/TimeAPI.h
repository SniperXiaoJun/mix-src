

#ifndef _API_TIME_H
#define _API_TIME_H


#ifdef __cplusplus
// CPP func
#include <string>
using namespace std;

//string to time_t
//时间格式  2009-3-24
int API_StringToTime(const string &strDateStr,time_t &timeData);

//time_t to string
int API_TimeToString(string &strDateStr,const time_t &timeData);

//string to time_t   
//	时间格式 2009-3-24 0:00:08 或 2009-3-24
int API_StringToTimeEX(const string &strDateStr,time_t &timeData);

//time_t to string 时间格式 2009-3-24 0:00:08 
int API_TimeToStringEX(string &strDateStr,const time_t &timeData);

#endif


#ifdef __cplusplus
extern "C"{
#endif
//	//************************************************************
//	//FILETIME, SYSTEMTIME 与 time_t 相互转换 
//	//#####SYSTEMTIME 与 FILETIME相互转换##### 
//	//可以使用系统函数
//	//FileTimeToSystemTime(&ftcreate,&stcreate);  
//	//参数：
//	//(lpFileTime As FILETIME, lpSystemTime As SYSTEMTIME) 
//	//说明 
//	//根据一个FILETIME结构的内容，装载一个SYSTEMTIME结构 
//	//返回值 
//	//Long，非零表示成功，零表示失败。会设置GetLastError 
//	//参数表 
//	//参数 类型及说明 
//	//lpFileTime FILETIME，包含了文件时间的一个结构 
//	//lpSystemTime SYSTEMTIME，用于装载系统时间信息的一个结构
//	//#####SYSTEMTIME 与 time_t相互转换#####
//	//#### Time_tToSystemTime ####
//
	#include <Windows.h>

	void TimetToSystemTime( time_t t, LPSYSTEMTIME pst);
	void SystemTimeToTime_t( SYSTEMTIME st, time_t *pt);
	void  FileTimeToTime_t(  FILETIME  ft,  time_t  *t);

	int GetNetTime_T(unsigned long long * pulTime);
	int SetLocalTime_T(unsigned long long ulTime);
	void GetLocalTime_T(unsigned long long * pulTime);

#ifdef __cplusplus
}
#endif



#endif