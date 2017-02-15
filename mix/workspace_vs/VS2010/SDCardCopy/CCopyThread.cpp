#include "CCopyThread.h"
#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QTime>
#include <QDebug>

CCopyThread::CCopyThread(QObject *parent)
: QThread(parent)
{

}

CCopyThread::~CCopyThread()
{

}

void CCopyThread::run()
{
	//QFile fileOld(m_strFileNameOld);

	//QFile fileNew(m_strFileNameNew);

	//quint64 fileLength = QFileInfo(m_strFileNameOld).size();

	//quint64 filePos = 0;

	QTime time1 = QTime::currentTime();

	TraverseFun(m_strFileNameOld);

	QTime time2 = QTime::currentTime();

	qDebug("timer :%s-%s",time1.toString().toAscii().constData(), time2.toString().toAscii().constData());

	//int maxByte = 1 * 102;

	//int readByteNum = 0;

	//QByteArray byteArray;

	//if (!fileOld.open(QIODevice::ReadOnly))
	//{
	//	return;
	//}

	//if (!fileNew.open(QIODevice::WriteOnly | QIODevice::Append))
	//{
	//	return;
	//}

	//for(filePos; filePos < fileLength; filePos += readByteNum)
	//{
	//	byteArray = fileOld.read(maxByte);
	//	readByteNum = byteArray.count();
	//	fileNew.write(byteArray);
	//	emit SignalPassByte((filePos * 100 )/fileLength);
	//}
	//emit SignalPassByte(100);


}

int CCopyThread::SetFileNameOld(QString fileName)
{
	m_strFileNameOld = fileName;
	return 0;
}

int CCopyThread::SetFileNameNew(QString fileName)
{
	m_strFileNameNew = fileName;
	return 0;
}

QString CCopyThread::GetFileNameNew()
{
	return m_strFileNameNew;
}

QString CCopyThread::GetFileNameOld()
{
	return m_strFileNameOld;
}

void CCopyThread::TraverseFun(QString filename)
{
	QFile fileOld(filename);

	if(QFileInfo(filename).isDir())
	{
		QString filenameNew = filename;

		filenameNew.replace(m_strFileNameOld, m_strFileNameNew);

		QDir().mkdir(filenameNew);

		emit SignalPassByte(100, filename, filenameNew);

		QDir dir(filename);

		QList<QFileInfo> list = dir.entryInfoList();

		for(int i = 0; i < list.count(); i++)
		{
			QString str = list.at(i).fileName();
			if(str == "." || str == "..")
			{
				continue ;
			}

			TraverseFun(list.at(i).absoluteFilePath());
		}
	}
	else
	{
		QString filenameNew = filename;

		filenameNew.replace(m_strFileNameOld, m_strFileNameNew);

		QFile fileNew(filenameNew);

		quint64 fileLength = QFileInfo(filename).size();

		quint64 filePos = 0;

		int maxByte = 1 * 1000 * 1024;

		int readByteNum = 0;

		QByteArray byteArray;

		if (!fileOld.open(QIODevice::ReadOnly))
		{
			return;
		}

		if (!fileNew.open(QIODevice::WriteOnly | QIODevice::Append))
		{
			return;
		}

		for(filePos; filePos < fileLength; filePos += readByteNum)
		{
			byteArray = fileOld.read(maxByte);
			readByteNum = byteArray.count();
			fileNew.write(byteArray);
			emit SignalPassByte((filePos * 100 )/fileLength, filename, filenameNew);
		}
		emit SignalPassByte(100, filename, filenameNew);

		fileNew.close();
		fileOld.close();
	}
}