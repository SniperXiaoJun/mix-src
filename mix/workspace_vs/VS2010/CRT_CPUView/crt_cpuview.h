#ifndef CRT_CPUVIEW_H
#define CRT_CPUVIEW_H

#include <QtGui/QMainWindow>
#include "ui_crt_cpuview.h"

#include <QPainter>
#include <QPaintEvent>
#include <QLabel>
#include <QPixmap>

#include <qtimer>

class CRT_CPUView : public QWidget
{
	Q_OBJECT

public:
	CRT_CPUView(QWidget *parent = 0, Qt::WFlags flags = 0);
	~CRT_CPUView();

	//绘制格子
	void drawGrid(QPainter &painter);

	//绘制曲线
	void drawCurves(QPainter &painter);

	//绘制事件
	void paintEvent(QPaintEvent*event);
	//定时器事件
	void timerEvent(QTimerEvent*event);


	public slots:
		//开始绘图
		void SlotOpenDraw();
		//取消绘图
		void SlotCloseDraw();

		void SlotTimeout();

		void SlotStartTimer();
			
		void SlotStopTimer();

private:
	Ui::CRT_CPUViewClass ui;

	int m_iTimerId;         //定义QObjeet定时器 
	int m_iXPos;            //实时数据曲线的横坐标
	int m_iDisplayDataLYPos;   //实时数据啮线的最新点数据
	int m_iDisplayDataFYPos;   //实时数据曲线的次新点数据

	int m_iDisplayDataCharge;  //最新点数据向次新点数据的中转变量

	bool m_bClose;             //绘制与初始化判断逻辑变量

	QPixmap m_pixmap; 

	QTimer * m_pTimer;

	//屏幕分辨率
	int m_iActScreenX;
    int m_iActScreenY;

};

#endif // CRT_CPUVIEW_H
