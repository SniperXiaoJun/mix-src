
#include "TimeAPI.h"
#include <time.h>
#include <stdio.h>
#include <Windows.h>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <TCHAR.H>
#include <winsock.h>

#define WIN32_LEAN_AND_MEAN

#pragma comment (lib,"Ws2_32")


#define UNICODE
#define _UNICODE

#define _countof(array) (sizeof(array)/sizeof(array[0]))
#define HIGHTIME		21968699 // 21968708 // Jan 1, 1900 FILETIME.highTime
#define LOWTIME			4259332096 // 1604626432 // Jan 1, 1900 FILETIME.lowtime

using namespace std;

//NTP�������б�
struct NISTSVR{
	int     key;	//���
	in_addr addr;	//IP��ַ
	LPCTSTR server;	//����
	LPCTSTR info;	//��Ϣ
} NISTSVRSARY[] = {
	{ 0, {0,0,0,0}, NULL, NULL},
	{ 1, {129,6,15,28}, _T("time-a.nist.gov"),_T("NIST����ʿ������������") },
	{ 2, {129,6,15,29}, _T("time-b.nist.gov"),_T("NIST����ʿ������������") },
	{ 3, {132,163,4,101}, _T("time-a.timefreq.bldrdoc.gov"),_T("NIST���������У�����������") },
	{ 4, {132,163,4,102}, _T("time-b.timefreq.bldrdoc.gov"),_T("NIST���������У�����������") },
	{ 5, {132,163,4,103}, _T("time-c.timefreq.bldrdoc.gov"),_T("NIST���������У�����������") },
	{ 6, {128,138,140,44}, _T("tutcnist.colorado.edu"),_T("���������ѧ����������") },
	{ 7, {192,43,244,18}, _T("time.nist.gov"),_T("NCAR���������У�����������") },
	{ 8, {131,107,1,10}, _T("time-nw.nist.gov"),_T("Microsoft�����ɵ£���ʢ����") },
	{ 9, {208,184,49,129}, _T("nist1.nyc.certifiedtime.com"),_T("Abovnet��ŦԼ��") },
};

//��ѡ���NTP������
static int choice = 1;

BOOL UpdateSysTime(DWORD dwTime)
{
	UINT64 uiCurTime, uiBaseTime, uiResult;
	SYSTEMTIME st;

	uiBaseTime = ((UINT64) HIGHTIME << 32) + LOWTIME;

	uiCurTime = (UINT64)dwTime * (UINT64)10000000;
	uiResult = uiBaseTime + uiCurTime;

	FileTimeToSystemTime((LPFILETIME)&uiResult, &st);

	return SetLocalTime(&st);
}

BOOL GetTimeFromServer(DWORD *lpdwTime)
{
	*lpdwTime = 0;
	BOOL bReturn= FALSE;

	SOCKET sSock = socket(AF_INET, SOCK_STREAM, 0);
	if(INVALID_SOCKET != sSock)
	{
		struct sockaddr_in sin;

		memcpy(&sin.sin_addr, &NISTSVRSARY[choice].addr, sizeof(in_addr));
		sin.sin_family = AF_INET;
		sin.sin_port = htons(IPPORT_TIMESERVER);

		printf( "\n    ...Waiting Connection...\n");

		if(0 == connect(sSock, (struct sockaddr *) &sin, sizeof(struct sockaddr_in)))
		{
			printf( "    ***Connected***\n");
			int iResult, iRead;

			for(iRead = 0; iRead < 4; iRead += iResult)
			{
				iResult = recv(sSock, (char*)lpdwTime + iRead, 4 - iRead, 0);
				if(iResult < 1)
					break;
			}

			if(4 == iRead)
			{
				*lpdwTime = ntohl(*lpdwTime);

				*lpdwTime -= 2208988800; // �Լ���ӵ�

				bReturn = TRUE;
			}else
				printf( "    Error getting time!\n");
		}else
			printf( "    ***Connection Failed***\n");


		closesocket(sSock);
	}

	return bReturn;
}


int GetNetTime_T(unsigned long long * pulTime) 
{ 
	DWORD time;

	BOOL bRet = FALSE;

	WSADATA WSAData;
	if(WSAStartup (MAKEWORD(1,1), &WSAData) != 0)
	{
		printf("WSAStartup failed.\n");
		WSACleanup();
	}
	else
	{
		bRet = GetTimeFromServer(&time);

		*pulTime = time;

		WSACleanup();
	}

	return (!bRet);
} 


    //string to time_t
    //ʱ���ʽ  2009-3-24

int API_StringToTime(const string &strDateStr,time_t &timeData)
{
    char *pBeginPos = (char*) strDateStr.c_str();
    char *pPos = strstr(pBeginPos,"-");
    if(pPos == NULL)
    {
        return -1;
    }
    int iYear = atoi(pBeginPos);
    int iMonth = atoi(pPos + 1);
 
    pPos = strstr(pPos + 1,"-");
    if(pPos == NULL)
    {
        return -1;
    }
 
    int iDay = atoi(pPos + 1);
 
    struct tm sourcedate;
    memset((void*)&sourcedate,sizeof(sourcedate), 0);
    sourcedate.tm_mday = iDay;
    sourcedate.tm_mon = iMonth - 1; 
    sourcedate.tm_year = iYear - 1900;
    
    timeData = mktime(&sourcedate);  
 
    return 0;
}
 
    //time_t to string
int API_TimeToString(string &strDateStr,const time_t &timeData)
{
    char chTmp[15];
    memset(chTmp,sizeof(chTmp),0);
 
    struct tm *p;
    p = localtime(&timeData);
 
    p->tm_year = p->tm_year + 1900;
 
    p->tm_mon = p->tm_mon + 1;
 
 
    sprintf(chTmp,"%04d-%02d-%02d",
        p->tm_year, p->tm_mon, p->tm_mday);
 
    strDateStr = chTmp;
    return 0;
}

   //string to time_t   
   //ʱ���ʽ 2009-3-24 0:00:08 �� 2009-3-24
   
int API_StringToTimeEX(const string &strDateStr,time_t &timeData)
{
    char *pBeginPos = (char*) strDateStr.c_str();
    char *pPos = strstr(pBeginPos,"-");
    if(pPos == NULL)
    {
        printf("strDateStr[%s] err \n", strDateStr.c_str());
        return -1;
    }
    int iYear = atoi(pBeginPos);
    int iMonth = atoi(pPos + 1);
    pPos = strstr(pPos + 1,"-");
    if(pPos == NULL)
    {
        printf("strDateStr[%s] err \n", strDateStr.c_str());
        return -1;
    }
    int iDay = atoi(pPos + 1);
    int iHour=0;
    int iMin=0;
    int iSec=0;
    pPos = strstr(pPos + 1," ");
    //Ϊ�˼�����Щû��ȷ��ʱ�����
    if(pPos != NULL)
    {
        iHour=atoi(pPos + 1);
        pPos = strstr(pPos + 1,":");
        if(pPos != NULL)
        {
            iMin=atoi(pPos + 1);
            pPos = strstr(pPos + 1,":");
            if(pPos != NULL)
            {
                iSec=atoi(pPos + 1);
            }
        }
    }
 
    struct tm sourcedate;
    memset((void*)&sourcedate,sizeof(sourcedate),0);
    sourcedate.tm_sec = iSec;
    sourcedate.tm_min = iMin; 
    sourcedate.tm_hour = iHour;
    sourcedate.tm_mday = iDay;
    sourcedate.tm_mon = iMonth - 1; 
    sourcedate.tm_year = iYear - 1900;
    timeData = mktime(&sourcedate);  
    return 0;
}
/*
   time_t to string ʱ���ʽ 2009-3-24 0:00:08 
   */
int API_TimeToStringEX(string &strDateStr,const time_t &timeData)
{
    char chTmp[100];
    memset(chTmp,sizeof(chTmp),0);
    struct tm *p;
    p = localtime(&timeData);
    p->tm_year = p->tm_year + 1900;
    p->tm_mon = p->tm_mon + 1;
 
    sprintf(chTmp,"%04d-%02d-%02d %02d:%02d:%02d",
            p->tm_year, p->tm_mon, p->tm_mday,p->tm_hour,p->tm_min,p->tm_sec);
    strDateStr = chTmp;
    return 0;
}

//************************************************************
//FILETIME, SYSTEMTIME �� time_t �໥ת�� 

//#####SYSTEMTIME �� FILETIME�໥ת��##### 
//����ʹ��ϵͳ����
//FileTimeToSystemTime(&ftcreate,&stcreate);  

//������
//(lpFileTime As FILETIME, lpSystemTime As SYSTEMTIME) 
//˵�� 
//����һ��FILETIME�ṹ�����ݣ�װ��һ��SYSTEMTIME�ṹ 
//����ֵ 
//Long�������ʾ�ɹ������ʾʧ�ܡ�������GetLastError 
//������ 
//���� ���ͼ�˵�� 
//lpFileTime FILETIME���������ļ�ʱ���һ���ṹ 
//lpSystemTime SYSTEMTIME������װ��ϵͳʱ����Ϣ��һ���ṹ

//#####SYSTEMTIME �� time_t�໥ת��#####

//#### Time_tToSystemTime ####
void TimetToSystemTime( time_t t, LPSYSTEMTIME pst)
{
	FILETIME ft; 
	LONGLONG ll = Int32x32To64(t, 10000000) + 116444736000000000;
	ft.dwLowDateTime = (unsigned int) ll;
	ft.dwHighDateTime = (unsigned int)(ll >> 32);

	FileTimeToSystemTime( &ft, pst );
}

//#### SystemTimeToTime_t ####
void SystemTimeToTime_t( SYSTEMTIME st, time_t *pt )
{
	LONGLONG ll;
	FILETIME ft;
	ULARGE_INTEGER ui;

	SystemTimeToFileTime( &st, &ft );

	ui.LowPart = ft.dwLowDateTime;
	ui.HighPart = ft.dwHighDateTime;

	ll = (ft.dwHighDateTime << 32) + ft.dwLowDateTime;

	*pt = (unsigned int)((LONGLONG)(ui.QuadPart - 116444736000000000) / 10000000);
}

//#### FileTimeToTime_t ####
void  FileTimeToTime_t(  FILETIME  ft,  time_t  *t  )  
{  
	LONGLONG  ll;  

	ULARGE_INTEGER            ui;  
	ui.LowPart            =  ft.dwLowDateTime;  
	ui.HighPart            =  ft.dwHighDateTime;  

	ll            =  ft.dwHighDateTime  <<  32  +  ft.dwLowDateTime;  

	*t            =  ((LONGLONG)(ui.QuadPart  -  116444736000000000)  /  10000000);  
}  
//********************************************************************/

void GetLocalTime_T(unsigned long long * pulTime)
{
	SYSTEMTIME st;

	time_t time;

	GetSystemTime(&st);

	SystemTimeToTime_t(st, &time);

	*pulTime = time;
}

int SetLocalTime_T(unsigned long long ulTime)    // ����ʱ��Э�鷵�ص�ʱ������ϵͳʱ�� 
{ 
	SYSTEMTIME st;
	time_t time;
	BOOL bFlag = FALSE;

	ulTime += 8 * 60 * 60;              // ʱ��

	time = ulTime;

	TimetToSystemTime(time, &st);

	bFlag = SetLocalTime(&st);

	return !bFlag;
} 