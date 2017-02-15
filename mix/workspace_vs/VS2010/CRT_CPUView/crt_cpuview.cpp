#include "crt_cpuview.h"

#include <QPainter>
#include <QDesktopWidget>

#include <QApplication>

#include <QPixmapCache>

CRT_CPUView::CRT_CPUView(QWidget *parent, Qt::WFlags flags)
	: QWidget(parent, flags) 
{
	ui.setupUi(this);

	m_bClose = true;
	m_iTimerId = 0;
	m_iXPos = 0;
	m_iDisplayDataCharge = 0;
	m_iDisplayDataLYPos = 0;

	m_pTimer = new QTimer(this);

	connect(m_pTimer,SIGNAL(timeout()), this, SLOT(SlotTimeout()));

	//m_pTimer->start(300);

	//setAttribute(Qt::WA_OpaquePaintEvent);//不透明

	//setAttribute(Qt::WA_PaintOnScreen);


	QDesktopWidget* desktopWidget = QApplication::desktop();
    //获取可用桌面大小
    QRect deskRect = desktopWidget->availableGeometry();
    //获取设备屏幕大小
    QRect screenRect = desktopWidget->screenGeometry();

    m_iActScreenX = screenRect.width();
    m_iActScreenY = screenRect.height();

	m_pixmap = QPixmap(m_iActScreenX + 50, m_iActScreenY);

	//connect(ui.pushButton_Open, SIGNAL(clicked()), this, SLOT(SlotOpenDraw()));
	//connect(ui.pushButton_Close, SIGNAL(clicked()), this, SLOT(SlotCloseDraw()));
}

void CRT_CPUView::SlotStartTimer()
{
	m_pTimer->start(300);
}

void CRT_CPUView::SlotStopTimer()
{
	m_pTimer->stop();
}

CRT_CPUView::~CRT_CPUView()
{
	delete m_pTimer;
}

void CRT_CPUView::SlotTimeout()
{
	m_bClose = false;

	//m_pixmap.scaled(m_iActScreenX + 50,m_iActScreenY);

	repaint();

	QRegion reg(0,0,0,0);

	m_pixmap.scroll(-5, 0,m_pixmap.rect(),&reg);

	m_iDisplayDataLYPos = rand()%150 - 75;

	static int i = 0;

	//i++;

	//if(i%10 == 0)
	//{
	//	m_pixmap.save(QString::number(i) + "CPU__.bmp");
	//}
}


void CRT_CPUView::SlotOpenDraw()
{
	if(m_bClose)
	{
		m_bClose = false;

		m_iTimerId = startTimer(30); //设置每30ms产生一个定时事件
	}
}

void CRT_CPUView::SlotCloseDraw()
{
	if(!m_bClose)
	{
		m_bClose = true;
		killTimer(m_iTimerId);
		update();
	}
	
}
void CRT_CPUView::drawGrid(QPainter &painter)
{
	painter.setPen(Qt::green);
	for(int u=0;u<m_iActScreenY/2;u++)
	{
		if(u%50 == 0)
		{
			painter.drawLine(-5,u,0,u);
			painter.drawLine(-5,-u,0,-u);
		}
	}

	if(m_iXPos % 10 == 0 /*|| m_iXPos == 0*/)
	{
		painter.drawLine(-5,m_iActScreenY/2,-5,-m_iActScreenY/2);
	}
	++m_iXPos;
}

void CRT_CPUView::drawCurves(QPainter&painter)
{
	painter.setPen(Qt::red);

	//painter.setRenderHint(QPainter::Antialiasing);

	m_iDisplayDataFYPos = m_iDisplayDataCharge;
	m_iDisplayDataCharge = m_iDisplayDataLYPos;

	painter.drawLine(-5,-m_iDisplayDataFYPos,0,-m_iDisplayDataLYPos);
}

void CRT_CPUView::paintEvent(QPaintEvent*event)
{
	event->ignore();
	QPainter paint(&m_pixmap);

	paint.setRenderHint(QPainter::Antialiasing);

	paint.setViewport(0,0,m_iActScreenX,m_iActScreenY); //设置绘制设备的物理坐标

	paint.setWindow(QRect(-m_iActScreenX,-m_iActScreenY/2,m_iActScreenX,m_iActScreenY)); //设置画笔的逻辑坐标

	if(!m_bClose){
		drawGrid(paint);
		drawCurves(paint);

		QPainter painterWidget(this);

		painterWidget.setRenderHint(QPainter::Antialiasing);

		painterWidget.drawPixmap(width() - m_iActScreenX, (height() - m_iActScreenY)/2, m_pixmap);
	}
	else
	{
		m_iXPos = 0;
		m_iDisplayDataCharge = 0;
	}
}

void CRT_CPUView::timerEvent(QTimerEvent*event)
{
	if(event->timerId() == m_iTimerId){
		scroll(-5,0);
		//scroll(-5,0, QRect(0,0,width(),height()-5));
		
		m_iDisplayDataLYPos = rand()%150;
	}
	else
	{
		QWidget::timerEvent(event);
	}
}
