

#ifndef _API_TIME_H
#define _API_TIME_H


#ifdef __cplusplus
// CPP func
#include <string>
using namespace std;

//string to time_t
//ʱ���ʽ  2009-3-24
int API_StringToTime(const string &strDateStr,time_t &timeData);

//time_t to string
int API_TimeToString(string &strDateStr,const time_t &timeData);

//string to time_t   
//	ʱ���ʽ 2009-3-24 0:00:08 �� 2009-3-24
int API_StringToTimeEX(const string &strDateStr,time_t &timeData);

//time_t to string ʱ���ʽ 2009-3-24 0:00:08 
int API_TimeToStringEX(string &strDateStr,const time_t &timeData);

#endif

#endif