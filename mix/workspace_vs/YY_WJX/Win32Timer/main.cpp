

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

//#include <WinSock.h>

#pragma comment(lib,"Winmm.lib")

#define ONE_MILLI_SECOND 1
#define TWO_SECOND 2000

#define TIMER_ACCURACY 1


void PASCAL OneMilliSecondProc(UINT wTimerID, UINT msg,DWORD dwUser,DWORD dw1,DWORD dw2)
{
	printf("one milli Seconds\n");
}

int main()
{
	HANDLE hHandle;

	UINT wAccuracy = TIMER_ACCURACY;
	UINT wTimeRes_1ms,wTimerRes_2s;

	UINT timerid_1ms, timerid_2s;

	wTimeRes_1ms = 5000;
	wTimeRes_1ms = ONE_MILLI_SECOND;
	wTimerRes_2s = TWO_SECOND;

	if((timerid_2s = timeSetEvent(wTimerRes_2s,wAccuracy,(LPTIMECALLBACK)OneMilliSecondProc,(DWORD)(1), TIME_PERIODIC)) == 0)
	{
		printf("start\n");
	}
	else
	{
		printf("end!\n");
	}

	//timeKillEvent(timerid_2s);


	while(1)
	{
		printf("hello\n");
		Sleep(1000);
	}


	//system("rd c:\\123\\");

	//SOCKET s = socket(AF_INET,SOCK_DGRAM,0);

	//if(remove("1.txt")  == 0)
	//{
	//	printf("success");
	//}
	//else
	//{
	//	printf("false");
	//}



	return getchar();
}