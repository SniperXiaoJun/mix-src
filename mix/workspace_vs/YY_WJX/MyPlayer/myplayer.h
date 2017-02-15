//-------------------------------------------------------------------------------------
// 文件名: myplayer.cpp
// 创建人: Li Qiangqiang
// 日  期: 2011-2-10
// 描  述: 类定义，定义类MyPlayer
// 版  本: 1.0
//-------------------------------------------------------------------------------------
// 修改记录: 
// 修 改 人: 
// 修改日期: 
// 修改目的: 
//-------------------------------------------------------------------------------------

#ifndef MYPLAYER_H
#define MYPLAYER_H

#include <QtGui/QMainWindow>
#include <QUrl>
#include <QList>
#include <QFileDialog>
#include <QDesktopServices>
#include <Phonon>


#include "ui_myplayer.h"

class MyPlayer : public QMainWindow
{
	Q_OBJECT

public:
	MyPlayer(QWidget *parent = 0, Qt::WFlags flags = 0);
	~MyPlayer();

private slots:
    void playPause();
    void addFiles();
    void nextFile();
	void backFile();
    //void aboutToFinish();
    //void finished();

private:
	Ui::MyPlayerClass ui;

	Phonon::SeekSlider *seekSlider;              //::实现进度条 
	Phonon::VolumeSlider *volumeSlider;          //::实现声音条

	QList<Phonon::MediaSource> sources;          //::媒体源
    Phonon::MediaObject *mediaObject;            //::媒体接收槽
    Phonon::AudioOutput *audioOutput;            //::音频接收槽
    Phonon::MediaObject *metaInformationResolver;//::指向当前音频文件的指针

};

#endif // MYPLAYER_H
