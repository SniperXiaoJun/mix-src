//-------------------------------------------------------------------------------------
// �ļ���: main.cpp
// ������: Li Qiangqiang
// ��  ��: 2011-3-2
// ��  ��: main������������ڵ�
// ��  ��: 1.0
//-------------------------------------------------------------------------------------
// �޸ļ�¼: 
// �� �� ��: 
// �޸�����: 
// �޸�Ŀ��: 
//-------------------------------------------------------------------------------------
#include <QtGui>

#include "CMusicPlayer.h"


int main(int argv, char **args)
{
    QApplication app(argv, args);

    app.setApplicationName("Music Player");
    app.setQuitOnLastWindowClosed(true);

    CMusicPlayer w;
    w.show();

    return app.exec(); 
}

