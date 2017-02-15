//-------------------------------------------------------------------------------------
// 文件名: CMusicPlayer.h
// 创建人: Li Qiangqiang
// 日  期: 2011-3-2
// 描  述: 类实现，声明类CMusicPlayer
// 版  本: 1.0
//-------------------------------------------------------------------------------------
// 修改记录: 
// 修 改 人: 
// 修改日期: 
// 修改目的: 
//-------------------------------------------------------------------------------------

#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <phonon/audiooutput.h>
#include <phonon/seekslider.h>
#include <phonon/mediaobject.h>
#include <phonon/volumeslider.h>
#include <phonon/backendcapabilities.h>
#include <QList>

QT_BEGIN_NAMESPACE
class QAction;
class QTableWidget;
class QLCDNumber;
QT_END_NAMESPACE



class CMusicPlayer : public QMainWindow
{
    Q_OBJECT

public:
    CMusicPlayer();
	~CMusicPlayer();

    QSize sizeHint() const {
        return QSize(500, 300);
    }

private slots:
    void addFiles();
    void about();

    void stateChanged(Phonon::State newState, Phonon::State oldState);
    void tick(qint64 time);
    void sourceChanged(const Phonon::MediaSource &source);
    void metaStateChanged(Phonon::State newState, Phonon::State oldState);
    void aboutToFinish();
    void tableClicked(int row, int column);


private:
    void setupActions();
    void setupMenus();
    void setupUi();    


    Phonon::SeekSlider *seekSlider;                   //::
    Phonon::MediaObject *mediaObject;                 //::
    Phonon::MediaObject *metaInformationResolver;     //::
    Phonon::AudioOutput *audioOutput;                 //::
    Phonon::VolumeSlider *volumeSlider;               //::
    QList<Phonon::MediaSource> sources;               //::


    QAction *playAction;                              //::
    QAction *pauseAction;                             //::
    QAction *stopAction;                              //::
    QAction *nextAction;                              //::
    QAction *previousAction;                          //::
    QAction *addFilesAction;                          //::
    QAction *exitAction;                              //::
    QAction *aboutAction;                             //::
    QAction *aboutQtAction;                           //::
    QLCDNumber *timeLcd;                              //::
    QTableWidget *musicTable;                         //::
};

#endif
