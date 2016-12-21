

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


#ifdef __cplusplus
extern "C"{
#endif
//	//************************************************************
//	//FILETIME, SYSTEMTIME �� time_t �໥ת�� 
//	//#####SYSTEMTIME �� FILETIME�໥ת��##### 
//	//����ʹ��ϵͳ����
//	//FileTimeToSystemTime(&ftcreate,&stcreate);  
//	//������
//	//(lpFileTime As FILETIME, lpSystemTime As SYSTEMTIME) 
//	//˵�� 
//	//����һ��FILETIME�ṹ�����ݣ�װ��һ��SYSTEMTIME�ṹ 
//	//����ֵ 
//	//Long�������ʾ�ɹ������ʾʧ�ܡ�������GetLastError 
//	//������ 
//	//���� ���ͼ�˵�� 
//	//lpFileTime FILETIME���������ļ�ʱ���һ���ṹ 
//	//lpSystemTime SYSTEMTIME������װ��ϵͳʱ����Ϣ��һ���ṹ
//	//#####SYSTEMTIME �� time_t�໥ת��#####
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