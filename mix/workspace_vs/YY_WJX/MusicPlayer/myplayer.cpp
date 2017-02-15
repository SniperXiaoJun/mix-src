//-------------------------------------------------------------------------------------
// �ļ���: myplayer.cpp
// ������: Li Qiangqiang
// ��  ��: 2011-2-10
// ��  ��: ��ʵ�֣�ʵ����MyPlayer
// ��  ��: 1.0
//-------------------------------------------------------------------------------------
// �޸ļ�¼: 
// �� �� ��: 
// �޸�����: 
// �޸�Ŀ��: 
//-------------------------------------------------------------------------------------
#include "myplayer.h"

MyPlayer::MyPlayer(QWidget *parent, Qt::WFlags flags)
	: QMainWindow(parent, flags)
{
	ui.setupUi(this);

    audioOutput = new Phonon::AudioOutput(Phonon::MusicCategory, this->ui.widget);
    mediaObject = new Phonon::MediaObject(this->ui.widget);
	metaInformationResolver = new Phonon::MediaObject(this->ui.widget);
    Phonon::createPath(mediaObject, audioOutput);

	seekSlider = new Phonon::SeekSlider(this);
	seekSlider->setMediaObject(mediaObject);
    volumeSlider = new Phonon::VolumeSlider(this);
    volumeSlider->setAudioOutput(audioOutput);

    ui.gridLayout->addWidget(seekSlider, 2, 0, 1, 3);
    ui.gridLayout->addWidget(volumeSlider, 2, 3, 1, 2);

	connect(this->ui.pushButtonAdd, SIGNAL(clicked()), this, SLOT(addFiles()));
	connect(this->ui.pushButtonBack, SIGNAL(clicked()), this, SLOT(backFile()));
	connect(this->ui.pushButtonDel, SIGNAL(clicked()), this, SLOT());
	connect(this->ui.pushButtonNext, SIGNAL(clicked()), this, SLOT(nextFile()));
	connect(this->ui.pushButtonPlay, SIGNAL(clicked()), this, SLOT(playPause()));
}

MyPlayer::~MyPlayer()
{

}

//////////////////////////////////////////////////////////////////////
// void MyPlayer::playPause()
// ���������
// ��
// ���������
// ��
// ˵����
// ʵ�ֲ�������ͣ����(��)
// ����ֵ��
// ��
// ������
// 2011/2/10 ��ǿǿ
//////////////////////////////////////////////////////////////////////
void MyPlayer::playPause()
{
    switch (mediaObject->state()){
        case Phonon::PlayingState:
            mediaObject->pause();
            this->ui.pushButtonPlay->setChecked(false);
			this->ui.pushButtonPlay->setText(QString::fromLocal8Bit("����"));
            break;
        case Phonon::PausedState:
            mediaObject->play();
			this->ui.pushButtonPlay->setText(QString::fromLocal8Bit("��ͣ"));
            break;
        case Phonon::StoppedState:
            mediaObject->play();
			this->ui.pushButtonPlay->setText(QString::fromLocal8Bit("��ͣ"));
            break;
        case Phonon::LoadingState:
            this->ui.pushButtonPlay->setChecked(false);
            break;
    }
}

//////////////////////////////////////////////////////////////////////
// void MyPlayer::addFiles()
// ���������
// ��
// ���������
// ��
// ˵����
// ʵ�����һ���ļ�(��)
// ����ֵ��
// ��
// ������
// 2011/2/10 ��ǿǿ
//////////////////////////////////////////////////////////////////////
void MyPlayer::addFiles()
{
    QStringList files = QFileDialog::getOpenFileNames(this, tr("Select Music Files"),
        QDesktopServices::storageLocation(QDesktopServices::MusicLocation));
	
    this->ui.pushButtonPlay->setChecked(false);
    if (files.isEmpty())
        return;
    int index = sources.size();
    foreach (QString string, files) 
	{
        Phonon::MediaSource source(string);
        sources.append(source);
		m_pListItem = new QListWidgetItem(string.section("/",-1),this->ui.listWidget);
    }
    if (!sources.isEmpty())
	{
        metaInformationResolver->setCurrentSource(sources.at(index));
        mediaObject->setCurrentSource(metaInformationResolver->currentSource());
		this->setWindowTitle(this->ui.listWidget->item(index)->text());
    }

	printf("%d\n",index);
} 

//////////////////////////////////////////////////////////////////////
// void MyPlayer::nextFile()
// ���������
// ��
// ���������
// ��
// ˵����
// ʵ�ֲ�����һ���ļ�(��)
// ����ֵ��
// ��
// ������
// 2011/2/10 ��ǿǿ
//////////////////////////////////////////////////////////////////////
void MyPlayer::nextFile()
{    

	if(0 == sources.size())
	{
		return;
	}
    int index = (sources.indexOf(mediaObject->currentSource()) + 1) % sources.size();    

    if (sources.size() > index) 
    {         
        mediaObject->stop();         
        mediaObject->setCurrentSource(sources.at(index));         
        mediaObject->play();     
		this->setWindowTitle(this->ui.listWidget->item(index)->text());
		QIcon icon;
        icon.addFile(QString::fromUtf8(":/MusicPlayer/Resources/vocol.png"), QSize(), QIcon::Normal, QIcon::Off);
        this->ui.listWidget->item(index)->setIcon(icon);
    }

	printf("%d\n",index);

}

//////////////////////////////////////////////////////////////////////
// void MyPlayer::backFile()
// ���������
// ��
// ���������
// ��
// ˵����
// ʵ�ֲ�����һ���ļ�(��)
// ����ֵ��
// ��
// ������
// 2011/2/10 ��ǿǿ
//////////////////////////////////////////////////////////////////////
void MyPlayer::backFile()
{    
	if(0 == sources.size())
	{
		return;
	}
    int index = (sources.indexOf(mediaObject->currentSource()) - 1 + sources.size()) % sources.size();    

    if (sources.size() > index) 
    {         
         mediaObject->stop();         
         mediaObject->setCurrentSource(sources.at(index));         
         mediaObject->play();     
		 this->setWindowTitle(this->ui.listWidget->item(index)->text());
    }

	printf("%d\n",index);

}

