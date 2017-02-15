/**********************************************************************************
*　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　 *
* Permission to use, copy, modify, and distribute this software and its         *
* documentation under the terms of the GNU General Public License is hereby     *
* granted. No representations are made about the suitability of this software   *
* for any purpose. It is provided "as is" without express or implied warranty.  *
* See http://www.gnu.org/copyleft/gpl.html for more details.                    *
*　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　 *
* All I ask is that if you use LRTimer in your project retain the　　　　　　　 *
* copyright notice. If you have any comments and suggestions please email me    *
* max[at]remoteSOS[dot]com　　　　　　　　　　　　　　　　　　　　　　　　　　  *
*　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　　 *
**********************************************************************************/

#ifndef LRTIMER_H__
#define LRTIMER_H__
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0500
#endif
// compile with: /MT /D "_X86_" /c
// processor: x86
#include <windows.h>
#include <process.h>
/* _beginthread, _endthread */
#include <stdio.h>
#include <assert.h>
// define a second in terms of 100ns - used with waitable timer API
#define _SECOND 10000
typedef VOID (*LRTCallbackEventProc)(VOID*);
class LRTimer
{
public:
	// default constructor with 1 second interval
	LRTimer(DWORD dwInterval=1000);
	// default destructor
	~LRTimer();

	// starts timer by creating new thread. interval must be set earlier
	VOID start();

	// starts timer with given interval in miliseconds
	VOID start(DWORD _interval_ms);

	// stops the timer
	VOID stop();

	// sets time interval in miliseconds
	VOID setInterval(DWORD _interval_ms);

	// returns time interval in ms
	DWORD getInterval();

	// sets function that will be called on time expiration
	VOID setCallbackProc(LRTCallbackEventProc pcbEventProc,VOID* pcbParam);
	// returns true if LRtimer is currently running
	BOOL isRunning();
	// It should be used if the worker class will use CRT functions
	static HANDLE CrtCreateThread(LPSECURITY_ATTRIBUTES lpsa, DWORD dwStackSize, LPTHREAD_START_ROUTINE pfnThreadProc, void *pvParam, DWORD dwCreationFlags, DWORD *pdwThreadId) throw()
	{
		// sanity check for pdwThreadId
		assert(sizeof(DWORD) == sizeof(unsigned int));
		// _beginthreadex calls CreateThread which will set the last error value before it returns
		return (HANDLE) _beginthreadex(lpsa, dwStackSize, (unsigned int (__stdcall *)(void *)) pfnThreadProc, pvParam, dwCreationFlags, (unsigned int *) pdwThreadId);
	}
private:
	DWORD m_dwInterval; // interval between alarms
	LRTCallbackEventProc m_pCallback; // pointer to user callback function
	VOID *m_pcbParam; // pointer to user callback parameter
	BOOL m_bRunning;  // timer running state
	HANDLE m_hTimerThread; // handle to timer thread
	DWORD m_iID; // timer thread id - added for compatibility with Win95/98
	// timer clocking tread runtine
	virtual DWORD WINAPI timerThread();
	// wrapper to thread runtine so it can be used within a class
	static DWORD WINAPI timerThreadAdapter(PVOID _this)
	{
		return ((LRTimer*) _this)->timerThread();
	}
	// timer callback APC procedure called when timer is signaled
	virtual VOID CALLBACK TimerAPCProc(LPVOID, DWORD, DWORD);
	// wrapper to callback APC procedure so it can be used within a class
	static VOID CALLBACK TimerAPCProcAdapter(PVOID _this, DWORD a1=0, DWORD a2=0)
	{
		((LRTimer*) _this)->TimerAPCProc( NULL, a1, a2 );
	}
};
#endif
