#include "csimple.h"
#include "common.h"
#include "aygshell.h"
#include <winbase.h>
#include <QTextStream>
#include <QFile.h>
#include <QtGui/QApplication>

int main(int argc, char *argv[])
{
//#ifndef _DEBUG
//	Handle hMutex = CreateMutex(NULL, TRUE, _T("CSimple"));
//#else
//	Handle hMutex = CreateMutex(NULL, TRUE, _T("CSimple"));
//#endif
//	if (GetLastError() == ERROR_ALREADY_EXISTS)
//	{
//		QFile file("out_1.txt");
//		
//		if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
//			return 1;
//
//		QTextStream out(&file);
//		out <<"1123";
//
//		file.close();
//
//
//		CloseHandle(hMutex);
//		hMutex = NULL;
//		return FALSE;
//	}
	QApplication a(argc, argv);
	CSimple w;

	//QObject::connect(&a, SIGNAL(focusChanged( QWidget *, QWidget *)),
	//	&w, SLOT(FocusChangedSlot( QWidget *, QWidget *)));

	//{
	//	QFile file("out_2.txt");
	//	
	//	if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
	//		return 1;

	//	QTextStream out(&file);
	//	out <<"1123";

	//	file.close();
	//}

	//HMENU hMenu = NULL;
	//HWND hWndMB = NULL;
	//hWndMB = SHFindMenuBar(w.winId());
	//TBBUTTONINFO tbbi = {0};
	//tbbi.cbSize = sizeof(TBBUTTONINFO);
	//tbbi.pszText = _T("²Ëµ¥");
	//::SendMessageW(hWndMB,TB_GETBUTTONINFO,1,(LPARAM)&tbbi);


	w.showFullScreen();
	return a.exec();
}
