
#include <stdio.h>
#include <stdlib.h>

#define WINDOWS

#ifdef WINDOWS
#include <winbase.h>
#include <windows.h>
#else
#include <dirent.h>
#include <sys/stat.h>
#endif

#ifdef WINDOWS

void delete_file(char * lpPath, char * type)
{
	char szFile[MAX_PATH];
	WIN32_FIND_DATA FindFileData;
	DWORD dwNum;
	wchar_t * pWCharFile;
	HANDLE hFind;

	strcpy(szFile,lpPath);
	strcat(szFile,"*.*");

	dwNum = MultiByteToWideChar(CP_ACP, 0, szFile, -1, NULL, 0);
	pWCharFile = malloc(sizeof(wchar_t) *dwNum);
	MultiByteToWideChar(CP_ACP, 0, szFile, -1, pWCharFile, dwNum);
	hFind = FindFirstFile(pWCharFile,&FindFileData);

	if(INVALID_HANDLE_VALUE == hFind)
	{
		return;
	}

	while(TRUE)
	{
		char tmp[MAX_PATH] = {0};
		int len;

		memset(szFile,0, MAX_PATH);
		len = WideCharToMultiByte(CP_ACP,0,FindFileData.cFileName,dwNum,NULL,0,NULL,NULL);
		WideCharToMultiByte(CP_ACP,0,FindFileData.cFileName,dwNum,tmp,len,NULL,NULL);

		if(FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			if(FindFileData.cFileName[0]!='.')
			{
				strcpy(szFile,lpPath);
				strcat(szFile,tmp);
				strcat(szFile,"\\");
				//delete_file(szFile, type); 子目录
			}
		}
		else
		{
			if(strstr(tmp, type))//判断类型是否一致
			{
				DWORD dwNum;
				wchar_t * pWCharFile;

				strcpy(szFile,lpPath);
				strcat(szFile,tmp);

				dwNum = MultiByteToWideChar(CP_ACP, 0, szFile, -1, NULL, 0);
				pWCharFile = malloc(sizeof(wchar_t) * dwNum);
				MultiByteToWideChar(CP_ACP, 0, szFile, -1, pWCharFile, dwNum);

				if(DeleteFile(pWCharFile) == 0)
				{
					//Error;
				}
			}
		}
		if(!FindNextFile(hFind,&FindFileData))
		{
			break;
		}
	}
	FindClose(hFind);
}
#else
void delete_file(char *path, char * type)
{
    struct dirent * ent = NULL;
    DIR *pDir;
    pDir = opendir(path);

    while (NULL != (ent = readdir(pDir))) {
        char sub_path[256 + 1] = { 0 };
        memcpy(sub_path, path, strlen(path));
        strcat(sub_path, "/");
        strcat(sub_path, ent->d_name);
        //delete_file(sub_path, type);    子目录
        if(strstr(sub_path, type))
        {
            remove(sub_path);
        }
    }
    closedir(pDir);
}
#endif



int main(int argc, char **argv)
{
	char * path = "\\data\\";

	char * type = ".txt";

	delete_file(path,type);

	return 0;
}

//
//
//#include <stdio.h>
//#include <stdlib.h>
//
//#define WINDOWS
//
//#ifdef WINDOWS
//#include <winbase.h>
//#include <windows.h>
//#else
//#include <stdio.h>
//#include <dirent.h>
//#include <sys/stat.h>
//#endif
//
//#ifdef WINDOWS
//void delete_file(char * lpPath, char * type)
//{
//	char szFile[MAX_PATH];
//	WIN32_FIND_DATA FindFileData;
//	DWORD dwNum;
//	wchar_t * pWCharFile;
//	HANDLE hFind;
//
//	strcpy(szFile,lpPath);
//	strcat(szFile,"*.*");
//
//	dwNum = MultiByteToWideChar(CP_ACP, 0, szFile, -1, NULL, 0);
//	pWCharFile = malloc(sizeof(wchar_t) *dwNum);
//	MultiByteToWideChar(CP_ACP, 0, szFile, -1, pWCharFile, dwNum);
//	hFind = FindFirstFile(pWCharFile,&FindFileData);
//
//	if(INVALID_HANDLE_VALUE == hFind)
//	{
//		return;
//	}
//
//	while(TRUE)
//	{
//		char tmp[MAX_PATH] = {0};
//		int len;
//
//		memset(szFile,0, MAX_PATH);
//		len = WideCharToMultiByte(CP_ACP,0,FindFileData.cFileName,dwNum,NULL,0,NULL,NULL);
//		WideCharToMultiByte(CP_ACP,0,FindFileData.cFileName,dwNum,tmp,len,NULL,NULL);
//
//		if(FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
//		{
//			if(FindFileData.cFileName[0]!='.')
//			{
//				strcpy(szFile,lpPath);
//				strcat(szFile,tmp);
//				strcat(szFile,"\\");
//				//delete_file(szFile, type); 子目录
//			}
//		}
//		else
//		{
//			if(strstr(tmp, type))//判断类型是否一致
//			{
//				DWORD dwNum;
//				wchar_t * pWCharFile;
//
//				strcpy(szFile,lpPath);
//				strcat(szFile,tmp);
//
//				dwNum = MultiByteToWideChar(CP_ACP, 0, szFile, -1, NULL, 0);
//				pWCharFile = malloc(sizeof(wchar_t) * dwNum);
//				MultiByteToWideChar(CP_ACP, 0, szFile, -1, pWCharFile, dwNum);
//
//				if(DeleteFile(pWCharFile) == 0)
//				{
//					//Error;
//				}
//			}
//		}
//		if(!FindNextFile(hFind,&FindFileData))
//		{
//			break;
//		}
//	}
//	FindClose(hFind);
//}
//#else
//void delete_file(char *path, char * type)
//{
//	struct dirent * ent = NULL;
//	DIR *pDir;
//	pDir = opendir(path);
//
//	while (NULL != (ent = readdir(pDir))) {
//		char sub_path[256 + 1] = { 0 };
//		memcpy(sub_path, path, strlen(path));
//		strcat(sub_path, "/");
//		strcat(sub_path, ent->d_name);
//		//delete_file(sub_path, type);    子目录
//		if(strstr(sub_path, type))
//		{
//			remove(sub_path);
//		}
//	}
//	closedir(pDir);
//}
//#endif
//
//
//
//int main(int argc, char **argv)
//{
//	char * path = "\\data\\";
//
//	char * type = ".txt";
//
//	delete_file(path,type);
//
//	return 0;
//}
