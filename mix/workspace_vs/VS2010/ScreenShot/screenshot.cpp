#include "screenshot.h"

#include "ScreenShot.h"
#include <QtGui>
 
ScreenShot::ScreenShot(QWidget *parent):
    QWidget(parent),  
    ui(new Ui::ScreenShotClass)  
{  
    ui->setupUi(this);  
    createWidgets();  
    createConnects();  
    createEventFilter();  
}  
 
ScreenShot::~ScreenShot()  
{  
    delete ui;  
 
    delete quit;  
    delete mini;  
    delete restore;  
    delete menu;  
    delete trayIcon;  
 
    delete fullScreenLabel;  
    delete shotScreenLabel;  
}  
 
bool ScreenShot::eventFilter(QObject *o, QEvent *e)  
{  
    if (o != fullScreenLabel)  
    {  
        return ScreenShot::eventFilter(o, e);  
    }  
 
    QMouseEvent *mouseEvent = static_cast<QMouseEvent*> (e);  


if ((mouseEvent->button() == Qt::LeftButton)  
      && (mouseEvent->type() == QEvent::MouseButtonPress)) 


leftMousePress = true; 

origin = mouseEvent->pos();   
      
        if (!rubberBand)      
        {     
            rubberBand = new QRubberBand(QRubberBand::Rectangle, fullScreenLabel);    
        }     
      
        rubberBand->setGeometry(QRect(origin,QSize()));   
        rubberBand->show();   
      
        return true;      
    }    

    if ((mouseEvent->type() == QEvent::MouseMove)  
        && (leftMousePress))  
    {  
        if (rubberBand)  
        {  
            rubberBand->setGeometry(QRect(origin, mouseEvent->pos()).normalized());  
        }  
 
        return true;  
    }  
鼠标左键松开

if ((mouseEvent->button() == Qt::LeftButton)  
 
       && (mouseEvent->type() == QEvent::MouseButtonRelease))  
 
   {  
鼠标标志位弹起

leftMousePress = false;  
   if (rubberBand)  
      {  
获取橡皮筋框的终止坐标

termination = mouseEvent->pos();  
            QRect rect = QRect(origin, termination);  
根据橡皮筋框截取全屏上的信息，并将其放入shotScreenLabel

            shotScreenLabel->setPixmap(fullScreenPixmap.grabWidget(fullScreenLabel,  
                                                                   rect.x(),  
                                                                   rect.y(),  
                                                                   rect.width(),  
                                                                   rect.height()));  
将shotScreenLabel的用户区大小固定为所截图片大小

            shotScreenLabel->setPixmap(fullScreenPixmap.grabWidget(fullScreenLabel,  
                                                                   rect.x(),  
                                                                   rect.y(),  
                                                                   rect.width(),  
                                                                   rect.height()));  
 
shotScreenLabel->setFixedSize(rect.width(), rect.height());  
            shotScreenLabel->show();  
 
            rubberBand->hide();  
            fullScreenLabel->hide();  
        }  
 
        return true;  
    }  
 
    return false;  
}  
 
/**  
  descr：实例化控件  
*/ 
void ScreenShot::createWidgets()  
{  
两个QLabel的父控件不能为this，否则截图信息会现在是主窗口中，无法正确显示

    fullScreenLabel = new QLabel();  
    shotScreenLabel = new QLabel();  
 
    rubberBand = new QRubberBand(QRubberBand::Rectangle, fullScreenLabel);  
 
    leftMousePress = false; 
初始化托盘控件并组装

    trayIcon = new QSystemTrayIcon(QIcon(tr(":/images/heart.svg")), this);  
    menu = new QMenu(this);  
    restore = new QAction(tr("Restore"), this);  
    mini = new QAction(tr("Mini"), this);  
    quit = new QAction(tr("Quit"), this);  
 
    menu->addAction(restore);  
    menu->addAction(mini);  
    menu->addAction(quit);  
    trayIcon->setContextMenu(menu); 
将托盘显示

trayIcon->show(); 
初始化托盘控件并组装

    savePixmap = new QAction(tr("save"), shotScreenLabel);  
 
    shotScreenLabel->addAction(savePixmap);  
    shotScreenLabel->setContextMenuPolicy(Qt::ActionsContextMenu);  
}  
 
void ScreenShot::createConnects()  
{  
主窗口信号槽

connect(ui->pbtnShot, SIGNAL(clicked()), this, SLOT(grapWindowScreen()));  
connect(ui->pbtnShotAndMin, SIGNAL(clicked()), this, SLOT(miniWindows()));  
connect(ui->pbtnMin, SIGNAL(clicked()), this, SLOT(miniWindows()));  
 
connect(savePixmap, SIGNAL(triggered()), this, SLOT(saveShotPixmap()));  
主窗口信号槽

托盘信号槽

    connect(restore, SIGNAL(triggered()), this, SLOT(restoreWindows()));  
    connect(mini, SIGNAL(triggered()), this, SLOT(miniWindows()));  
    connect(quit, SIGNAL(triggered()), this, SLOT(quitApplication()));  
 
}  
 
void ScreenShot::createEventFilter()  
{  
    fullScreenLabel->installEventFilter(this);  
}  
 
QString ScreenShot::getSaveShotPixmap()  
{  
    return QFileDialog::getSaveFileName(shotScreenLabel,  
                                        tr("Open Image"),  
                                        ".",  
                                        tr("Image Files(.JPG .PNG)"));  
}  
 
void ScreenShot::grapWindowScreen()  
{  
    if (!fullScreenLabel)  
    {  
        fullScreenLabel = new QLabel();  
    }  
获取全屏截图fullScreenPixmap，并将其放入fullScreenLabel

fullScreenPixmap = QPixmap::grabWindow(QApplication::desktop()->winId());  
fullScreenLabel->setPixmap(fullScreenPixmap); 
label全屏显示

    fullScreenLabel->showFullScreen();  
}  
 
void ScreenShot::miniWindows()  
{  
    showMinimized();  
    grapWindowScreen();  
}  
 
void ScreenShot::restoreWindows()  
{  
    showNormal();  
}  
 
void ScreenShot::quitApplication()  
{  
    qApp->quit();  
}  
 
void ScreenShot::saveShotPixmap()  
{  
    QString fileName = getSaveShotPixmap();  
 
    if (!fileName.isNull())  
    {  
        fullScreenPixmap.save(fileName);  
    }  
 
}