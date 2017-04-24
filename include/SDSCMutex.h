
// SDSCMutex.h
#ifndef _SDSC_MUTEX_H
#define _SDSC_MUTEX_H

#include <windows.h>
#include <TCHAR.h>


#ifdef __cplusplus
extern "C" {
#endif

DWORD SDSCWaitMutex
(
	IN TCHAR *pszMutexName,
	IN DWORD dwTime,
	OUT HANDLE *phMutex
);

	
void SDSCReleaseMutex
(
	IN HANDLE hMutex
);


DWORD SDSCCreateFileMap
(
	IN TCHAR *pszMapName,
	IN DWORD ulSize,
	OUT HANDLE *phMapping,
	OUT BOOL *pbNewMapping	
);


DWORD SDSCCreateFileMapMutex
(
	IN TCHAR *pszMutexName,
	IN TCHAR *pszMapName,
	IN DWORD ulSize,
	OUT HANDLE *phMapping,
	OUT BOOL *pbNewMapping	
);
	

DWORD SDSCWriteFileMap
(
	IN TCHAR *pszMapName,
	IN BYTE *pbData,
	IN DWORD ulSize
);

	
DWORD SDSCWriteFileMapMutex
(
	IN TCHAR *pszMutexName,
	IN TCHAR *pszMapName,
	IN BYTE *pbData,
	IN DWORD ulSize
);


DWORD SDSCReadFileMap
(
	IN TCHAR *pszMapName,
	OUT BYTE *pbData,
	IN DWORD ulSize
);
	

DWORD SDSCReadFileMapMutex
(
	IN TCHAR *pszMutexName,
	IN TCHAR *pszMapName,
	OUT BYTE *pbData,
	IN DWORD ulSize
);

#ifdef __cplusplus
}
#endif


#endif