//-------------------------------------------------------------------------------------
// �ļ���: main.cpp
// ������: Li Qiangqiang
// ��  ��: 2011-2-10
// ��  ��: ������
// ��  ��: 1.0
//-------------------------------------------------------------------------------------
// �޸ļ�¼: 
// �� �� ��: 
// �޸�����: 
// �޸�Ŀ��: 
//-------------------------------------------------------------------------------------

#include "myplayer.h"
#include <QtGui/QApplication>

int main(int argc, char *argv[])
{
	QApplication a(argc, argv);
	MyPlayer w;
	w.showMaximized();
	return a.exec();
}