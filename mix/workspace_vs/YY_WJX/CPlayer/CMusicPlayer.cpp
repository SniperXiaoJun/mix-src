//-------------------------------------------------------------------------------------
// 文件名: CMusicPlayer.cpp
// 创建人: Li Qiangqiang
// 日  期: 2011-3-2
// 描  述: 类实现，实现类CMusicPlayer
// 版  本: 1.0
//-------------------------------------------------------------------------------------
// 修改记录: 
// 修 改 人: 
// 修改日期: 
// 修改目的: 
//-------------------------------------------------------------------------------------

#include <QtGui>

#include "CMusicPlayer.h"

//////////////////////////////////////////////////////////////////////
// CMusicPlayer::CMusicPlayer()
// 输入参数：
// 无
// 输出参数：
// 无
// 说明：构造函数
// 返回值：
// 无
// 创建人
// 2011/3/2  李强强
//////////////////////////////////////////////////////////////////////
CMusicPlayer::CMusicPlayer()
{
    audioOutput = new Phonon::AudioOutput(Phonon::MusicCategory, this);
    mediaObject = new Phonon::MediaObject(this);
    metaInformationResolver = new Phonon::MediaObject(this);

    mediaObject->setTickInterval(1000);

    connect(mediaObject, SIGNAL(tick(qint64)), this, SLOT(tick(qint64)));
    connect(mediaObject, SIGNAL(stateChanged(Phonon::State,Phonon::State)),
            this, SLOT(stateChanged(Phonon::State,Phonon::State)));
    connect(metaInformationResolver, SIGNAL(stateChanged(Phonon::State,Phonon::State)),
            this, SLOT(metaStateChanged(Phonon::State,Phonon::State)));
    connect(mediaObject, SIGNAL(currentSourceChanged(Phonon::MediaSource)),
            this, SLOT(sourceChanged(Phonon::MediaSource)));
    connect(mediaObject, SIGNAL(aboutToFinish()), this, SLOT(aboutToFinish()));

    Phonon::createPath(mediaObject, audioOutput);


    setupActions();
    setupMenus();
    setupUi();
    timeLcd->display("00:00"); 
}


//////////////////////////////////////////////////////////////////////
// CMusicPlayer::~CMusicPlayer()
// 输入参数：
// 无
// 输出参数：
// 无
// 说明：析构函数
// 返回值：
// 无
// 创建人
// 2011/3/2  李强强
//////////////////////////////////////////////////////////////////////
CMusicPlayer::~CMusicPlayer()
{
 
}


//////////////////////////////////////////////////////////////////////
// void CMusicPlayer::addFiles()
// 输入参数：
// 无
// 输出参数：
// 无
// 说明：添加音乐播放文件
// 返回值：
// 无
// 创建人
// 2011/3/2  李强强
//////////////////////////////////////////////////////////////////////
void CMusicPlayer::addFiles()
{
    QStringList files = QFileDialog::getOpenFileNames(this, tr("Select Music Files"), 
        QDesktopServices::storageLocation(QDesktopServices::MusicLocation));

    if (files.isEmpty())
        return;

    int index = sources.size();
    foreach (QString string, files) {
            Phonon::MediaSource source(string);
        
        sources.append(source);
    } 
    if (!sources.isEmpty())
        metaInformationResolver->setCurrentSource(sources.at(index));

}

//////////////////////////////////////////////////////////////////////
// void CMusicPlayer::about()
// 输入参数：
// 无
// 输出参数：
// 无
// 说明：关于音乐播放器b 
// 返回值：
// 无
// 创建人
// 2011/3/2  李强强
//////////////////////////////////////////////////////////////////////
void CMusicPlayer::about()
{
    QMessageBox::information(this, tr("About Music Player"),
        tr("The Music Player example shows how to use Phonon - the multimedia"
           " framework that comes with Qt - to create a simple music player."));
}

//////////////////////////////////////////////////////////////////////
// void CMusicPlayer::addFiles()
// 输入参数：
// 无
// 输出参数：
// 无
// 说明：添加音乐播放文件
// 返回值：
// 无
// 创建人
// 2011/3/2  李强强
//////////////////////////////////////////////////////////////////////
void CMusicPlayer::stateChanged(Phonon::State newState, Phonon::State /* oldState */)
{
    switch (newState) {
        case Phonon::ErrorState:
            if (mediaObject->errorType() == Phonon::FatalError) {
                QMessageBox::warning(this, tr("Fatal Error"),
                mediaObject->errorString());
            } else {
                QMessageBox::warning(this, tr("Error"),
                mediaObject->errorString());
            }
            break;

        case Phonon::PlayingState:
                playAction->setEnabled(false);
                pauseAction->setEnabled(true);
                stopAction->setEnabled(true);
                break;
        case Phonon::StoppedState:
                stopAction->setEnabled(false);
                playAction->setEnabled(true);
                pauseAction->setEnabled(false);
                timeLcd->display("00:00");
                break;
        case Phonon::PausedState:
                pauseAction->setEnabled(false);
                stopAction->setEnabled(true);
                playAction->setEnabled(true);
                break;

        case Phonon::BufferingState:
                break;
        default:
            ;
    }
}


void CMusicPlayer::tick(qint64 time)
{
    QTime displayTime(0, (time / 60000) % 60, (time / 1000) % 60);

    timeLcd->display(displayTime.toString("mm:ss"));
}


//////////////////////////////////////////////////////////////////////
// void CMusicPlayer::addFiles()
// 输入参数：
// 无
// 输出参数：
// 无
// 说明：添加音乐播放文件
// 返回值：
// 无
// 创建人
// 2011/3/2  李强强
//////////////////////////////////////////////////////////////////////
void CMusicPlayer::tableClicked(int row, int /* column */)
{
    bool wasPlaying = mediaObject->state() == Phonon::PlayingState;

    mediaObject->stop();
    mediaObject->clearQueue();

    if (row >= sources.size())
        return;

    mediaObject->setCurrentSource(sources[row]);

    if (wasPlaying)
        mediaObject->play();
    else
        mediaObject->stop();
}


//////////////////////////////////////////////////////////////////////
// void CMusicPlayer::addFiles()
// 输入参数：
// 无
// 输出参数：
// 无
// 说明：添加音乐播放文件
// 返回值：
// 无
// 创建人
// 2011/3/2  李强强
//////////////////////////////////////////////////////////////////////
void CMusicPlayer::sourceChanged(const Phonon::MediaSource &source)
{
    musicTable->selectRow(sources.indexOf(source));
    timeLcd->display("00:00");
}


//////////////////////////////////////////////////////////////////////
// void CMusicPlayer::addFiles()
// 输入参数：
// 无
// 输出参数：
// 无
// 说明：添加音乐播放文件
// 返回值：
// 无
// 创建人
// 2011/3/2  李强强
//////////////////////////////////////////////////////////////////////
void CMusicPlayer::metaStateChanged(Phonon::State newState, Phonon::State /* oldState */)
{
    if (newState == Phonon::ErrorState) {
        QMessageBox::warning(this, tr("Error opening files"),
            metaInformationResolver->errorString());
        while (!sources.isEmpty() &&
               !(sources.takeLast() == metaInformationResolver->currentSource())) {}  /* loop */;
        return;
    }

    if (newState != Phonon::StoppedState && newState != Phonon::PausedState)
        return;

    if (metaInformationResolver->currentSource().type() == Phonon::MediaSource::Invalid)
            return;

    QMap<QString, QString> metaData = metaInformationResolver->metaData();

    QString title = metaData.value("TITLE");
    if (title == "")
        title = metaInformationResolver->currentSource().fileName();

    QTableWidgetItem *titleItem = new QTableWidgetItem(title);
    titleItem->setFlags(titleItem->flags() ^ Qt::ItemIsEditable);
    QTableWidgetItem *artistItem = new QTableWidgetItem(metaData.value("ARTIST"));
    artistItem->setFlags(artistItem->flags() ^ Qt::ItemIsEditable);
    QTableWidgetItem *albumItem = new QTableWidgetItem(metaData.value("ALBUM"));
    albumItem->setFlags(albumItem->flags() ^ Qt::ItemIsEditable);
    QTableWidgetItem *yearItem = new QTableWidgetItem(metaData.value("DATE"));
    yearItem->setFlags(yearItem->flags() ^ Qt::ItemIsEditable);


    int currentRow = musicTable->rowCount();
    musicTable->insertRow(currentRow);
    musicTable->setItem(currentRow, 0, titleItem);
    musicTable->setItem(currentRow, 1, artistItem);
    musicTable->setItem(currentRow, 2, albumItem);
    musicTable->setItem(currentRow, 3, yearItem);


    if (musicTable->selectedItems().isEmpty()) {
        musicTable->selectRow(0);
        mediaObject->setCurrentSource(metaInformationResolver->currentSource());
    }

    Phonon::MediaSource source = metaInformationResolver->currentSource();
    int index = sources.indexOf(metaInformationResolver->currentSource()) + 1;
    if (sources.size() > index) {
        metaInformationResolver->setCurrentSource(sources.at(index));
    }
    else {
        musicTable->resizeColumnsToContents();
        if (musicTable->columnWidth(0) > 300)
            musicTable->setColumnWidth(0, 300);
    }
}


//////////////////////////////////////////////////////////////////////
// void CMusicPlayer::addFiles()
// 输入参数：
// 无
// 输出参数：
// 无
// 说明：添加音乐播放文件
// 返回值：
// 无
// 创建人
// 2011/3/2  李强强
//////////////////////////////////////////////////////////////////////
void CMusicPlayer::aboutToFinish()
{
    int index = sources.indexOf(mediaObject->currentSource()) + 1;
    if (sources.size() > index) {
        mediaObject->enqueue(sources.at(index));
    }
}


//////////////////////////////////////////////////////////////////////
// void CMusicPlayer::addFiles()
// 输入参数：
// 无
// 输出参数：
// 无
// 说明：添加音乐播放文件
// 返回值：
// 无
// 创建人
// 2011/3/2  李强强
//////////////////////////////////////////////////////////////////////
void CMusicPlayer::setupActions()
{
    playAction = new QAction(style()->standardIcon(QStyle::SP_MediaPlay), tr("Play"), this);
    playAction->setShortcut(tr("Crl+P"));
    playAction->setDisabled(true);
    pauseAction = new QAction(style()->standardIcon(QStyle::SP_MediaPause), tr("Pause"), this);
    pauseAction->setShortcut(tr("Ctrl+A"));
    pauseAction->setDisabled(true);
    stopAction = new QAction(style()->standardIcon(QStyle::SP_MediaStop), tr("Stop"), this);
    stopAction->setShortcut(tr("Ctrl+S"));
    stopAction->setDisabled(true);
    nextAction = new QAction(style()->standardIcon(QStyle::SP_MediaSkipForward), tr("Next"), this);
    nextAction->setShortcut(tr("Ctrl+N"));
    previousAction = new QAction(style()->standardIcon(QStyle::SP_MediaSkipBackward), tr("Previous"), this);
    previousAction->setShortcut(tr("Ctrl+R"));
    addFilesAction = new QAction(tr("Add &Files"), this);
    addFilesAction->setShortcut(tr("Ctrl+F"));
    exitAction = new QAction(tr("E&xit"), this);
    exitAction->setShortcuts(QKeySequence::Quit);
    aboutAction = new QAction(tr("A&bout"), this);
    aboutAction->setShortcut(tr("Ctrl+B"));
    aboutQtAction = new QAction(tr("About &Qt"), this);
    aboutQtAction->setShortcut(tr("Ctrl+Q"));


    connect(playAction, SIGNAL(triggered()), mediaObject, SLOT(play()));
    connect(pauseAction, SIGNAL(triggered()), mediaObject, SLOT(pause()) );
    connect(stopAction, SIGNAL(triggered()), mediaObject, SLOT(stop()));

    connect(addFilesAction, SIGNAL(triggered()), this, SLOT(addFiles()));
    connect(exitAction, SIGNAL(triggered()), this, SLOT(close()));
    connect(aboutAction, SIGNAL(triggered()), this, SLOT(about()));
    connect(aboutQtAction, SIGNAL(triggered()), qApp, SLOT(aboutQt()));
}


//////////////////////////////////////////////////////////////////////
// void CMusicPlayer::addFiles()
// 输入参数：
// 无
// 输出参数：
// 无
// 说明：添加音乐播放文件
// 返回值：
// 无
// 创建人
// 2011/3/2  李强强
//////////////////////////////////////////////////////////////////////
void CMusicPlayer::setupMenus()
{
    QMenu *fileMenu = menuBar()->addMenu(tr("&File"));
    fileMenu->addAction(addFilesAction);
    fileMenu->addSeparator();
    fileMenu->addAction(exitAction);

    QMenu *aboutMenu = menuBar()->addMenu(tr("&Help"));
    aboutMenu->addAction(aboutAction);
    aboutMenu->addAction(aboutQtAction);
}

//////////////////////////////////////////////////////////////////////
// void CMusicPlayer::addFiles()
// 输入参数：
// 无
// 输出参数：
// 无
// 说明：添加音乐播放文件
// 返回值：
// 无
// 创建人
// 2011/3/2  李强强
//////////////////////////////////////////////////////////////////////
void CMusicPlayer::setupUi()
{

    QToolBar *bar = new QToolBar;

    bar->addAction(playAction);
    bar->addAction(pauseAction);
    bar->addAction(stopAction);
    

    seekSlider = new Phonon::SeekSlider(this);
    seekSlider->setMediaObject(mediaObject);

    volumeSlider = new Phonon::VolumeSlider(this);
    volumeSlider->setAudioOutput(audioOutput);

    volumeSlider->setSizePolicy(QSizePolicy::Maximum, QSizePolicy::Maximum);

    QLabel *volumeLabel = new QLabel;
    volumeLabel->setPixmap(QPixmap("images/volume.png"));

    QPalette palette;
    palette.setBrush(QPalette::Light, Qt::darkGray);

    timeLcd = new QLCDNumber;
    timeLcd->setPalette(palette);

    QStringList headers;
    headers << tr("Title") << tr("Artist") << tr("Album") << tr("Year");

    musicTable = new QTableWidget(0, 4);
    musicTable->setHorizontalHeaderLabels(headers);
    musicTable->setSelectionMode(QAbstractItemView::SingleSelection);
    musicTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    connect(musicTable, SIGNAL(cellPressed(int,int)),
            this, SLOT(tableClicked(int,int)));

    QHBoxLayout *seekerLayout = new QHBoxLayout;
    seekerLayout->addWidget(seekSlider);
    seekerLayout->addWidget(timeLcd);

    QHBoxLayout *playbackLayout = new QHBoxLayout;
    playbackLayout->addWidget(bar);
    playbackLayout->addStretch();
    playbackLayout->addWidget(volumeLabel);
    playbackLayout->addWidget(volumeSlider);

    QVBoxLayout *mainLayout = new QVBoxLayout;
    mainLayout->addWidget(musicTable);
    mainLayout->addLayout(seekerLayout);
    mainLayout->addLayout(playbackLayout);

    QWidget *widget = new QWidget;
    widget->setLayout(mainLayout);

    setCentralWidget(widget);
    setWindowTitle("Phonon Music Player");
}

