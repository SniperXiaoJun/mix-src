#include "mainwindow.h"

#include <QDesktopWidget>

#include <QApplication>

MainWindow::MainWindow(QWidget *parent)
	: QMainWindow(parent)
{
	ui.setupUi(this);

	connect(ui.pushButton_Open, SIGNAL(clicked()), ui.widget_1, SLOT(SlotStartTimer()));
	connect(ui.pushButton_Close, SIGNAL(clicked()), ui.widget_1, SLOT(SlotStopTimer()));

	connect(ui.pushButton_Open, SIGNAL(clicked()), ui.widget_2, SLOT(SlotStartTimer()));
	connect(ui.pushButton_Close, SIGNAL(clicked()), ui.widget_2, SLOT(SlotStopTimer()));

	connect(ui.pushButton_Open, SIGNAL(clicked()), ui.widget_3, SLOT(SlotStartTimer()));
	connect(ui.pushButton_Close, SIGNAL(clicked()), ui.widget_3, SLOT(SlotStopTimer()));

	connect(ui.pushButton_Open, SIGNAL(clicked()), ui.widget_4, SLOT(SlotStartTimer()));
	connect(ui.pushButton_Close, SIGNAL(clicked()), ui.widget_4, SLOT(SlotStopTimer()));

	m_pTimer = new QTimer(this);

	connect(m_pTimer, SIGNAL(timeout()), this, SLOT(SlotTimerOut()));

	m_pTimer->start(1000);
}

MainWindow::~MainWindow()
{
	delete m_pTimer;
}

void MainWindow::SlotTimerOut()
{
	static int i = 0;

	i++;

	QPixmap pixmap(width(),height());
	pixmap = QPixmap::grabWindow(QApplication::desktop()->winId());

	pixmap.save(QString::number(i) + "CPU.jpg");
}

void MainWindow::paintEvent(QPaintEvent*event)
{
	// ºöÂÔ

	// event->ignore();
}