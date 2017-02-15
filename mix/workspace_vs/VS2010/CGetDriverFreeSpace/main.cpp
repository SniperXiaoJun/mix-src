
#include <QtCore/QCoreApplication>
#include <windows.h>
#include <QDebug>


double GetDiskUsedSpace(QString driver)
{ 

	LPCWSTR lpcwstrDriver=(LPCWSTR)driver.utf16(); 

	ULARGE_INTEGER liFreeBytesAvailable, liTotalBytes, liTotalFreeBytes; 

	if( !GetDiskFreeSpaceEx( lpcwstrDriver, &liFreeBytesAvailable, &liTotalBytes, &liTotalFreeBytes) ) 
	{ 
		qDebug() << "ERROR: Call to GetDiskFreeSpaceEx() failed."; 
		return 0; 
	} 

	return (double)(liTotalBytes.QuadPart/1024.0/1024.0 - liTotalFreeBytes.QuadPart/1024.0/1024.0);  

} 


int main(int argc, char *argv[])
{
	QCoreApplication a(argc, argv);

	double freeSpace =GetDiskUsedSpace(QString("M:/"));
	qDebug() << QString::fromLocal8Bit("已用空间") << freeSpace<< "MB";//输出磁盘剩余空间大小




	return a.exec();
}
