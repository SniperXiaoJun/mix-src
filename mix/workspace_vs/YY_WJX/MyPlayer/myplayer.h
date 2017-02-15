//-------------------------------------------------------------------------------------
// �ļ���: myplayer.cpp
// ������: Li Qiangqiang
// ��  ��: 2011-2-10
// ��  ��: �ඨ�壬������MyPlayer
// ��  ��: 1.0
//-------------------------------------------------------------------------------------
// �޸ļ�¼: 
// �� �� ��: 
// �޸�����: 
// �޸�Ŀ��: 
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

	Phonon::SeekSlider *seekSlider;              //::ʵ�ֽ����� 
	Phonon::VolumeSlider *volumeSlider;          //::ʵ��������

	QList<Phonon::MediaSource> sources;          //::ý��Դ
    Phonon::MediaObject *mediaObject;            //::ý����ղ�
    Phonon::AudioOutput *audioOutput;            //::��Ƶ���ղ�
    Phonon::MediaObject *metaInformationResolver;//::ָ��ǰ��Ƶ�ļ���ָ��

};

#endif // MYPLAYER_H
