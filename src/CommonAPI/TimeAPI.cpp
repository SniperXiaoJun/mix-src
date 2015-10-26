
#include <time.h>
#include <stdio.h>
#include <string>

using namespace std;





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
   //时间格式 2009-3-24 0:00:08 或 2009-3-24
   
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
    //为了兼容有些没精确到时分秒的
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
   time_t to string 时间格式 2009-3-24 0:00:08 
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