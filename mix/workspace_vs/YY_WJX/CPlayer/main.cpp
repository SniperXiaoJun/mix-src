//-------------------------------------------------------------------------------------
// 文件名: main.cpp
// 创建人: Li Qiangqiang
// 日  期: 2011-3-2
// 描  述: main函数，函数入口点
// 版  本: 1.0
//-------------------------------------------------------------------------------------
// 修改记录: 
// 修 改 人: 
// 修改日期: 
// 修改目的: 
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

