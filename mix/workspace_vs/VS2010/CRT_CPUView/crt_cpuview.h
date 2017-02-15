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

	//���Ƹ���
	void drawGrid(QPainter &painter);

	//��������
	void drawCurves(QPainter &painter);

	//�����¼�
	void paintEvent(QPaintEvent*event);
	//��ʱ���¼�
	void timerEvent(QTimerEvent*event);


	public slots:
		//��ʼ��ͼ
		void SlotOpenDraw();
		//ȡ����ͼ
		void SlotCloseDraw();

		void SlotTimeout();

		void SlotStartTimer();
			
		void SlotStopTimer();

private:
	Ui::CRT_CPUViewClass ui;

	int m_iTimerId;         //����QObjeet��ʱ�� 
	int m_iXPos;            //ʵʱ�������ߵĺ�����
	int m_iDisplayDataLYPos;   //ʵʱ�������ߵ����µ�����
	int m_iDisplayDataFYPos;   //ʵʱ�������ߵĴ��µ�����

	int m_iDisplayDataCharge;  //���µ���������µ����ݵ���ת����

	bool m_bClose;             //�������ʼ���ж��߼�����

	QPixmap m_pixmap; 

	QTimer * m_pTimer;

	//��Ļ�ֱ���
	int m_iActScreenX;
    int m_iActScreenY;

};

#endif // CRT_CPUVIEW_H
