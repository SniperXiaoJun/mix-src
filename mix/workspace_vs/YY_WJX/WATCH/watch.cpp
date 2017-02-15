#include "watch.h"
#include "time.h"
#include "stdlib.h"

WATCH::WATCH(QWidget *parent, Qt::WFlags flags)
	: QMainWindow(parent, flags)
{
	ui.setupUi(this);

	now = NULL;

	int i, j, x, y;

	score = 0;

	i = j = x = y = 0;

	icon [0] = QIcon("1.png");
	icon [1] = QIcon("2.png");
	icon [2] = QIcon("3.png");
	icon [3] = QIcon("4.png");
	icon [4] = QIcon("5.png");
	icon [5] = QIcon("6.png");
	icon [6] = QIcon("7.png");
	icon [7] = QIcon("8.png");
	icon [8] = QIcon("9.png");
	icon [9] = QIcon("0.png");

	for(j = 0; j < 100; j ++)
	{
		qsrand(QTime::currentTime().msec() + QTime::currentTime().second() * 1000);
		ui.gridLayout->addWidget(&label[j], y, x, 1, 1);
		i = (qrand() + i + j + x + y) % 10;
		label[j].setIcon(icon[i]);
		label[j].setText(QString::number(i));
		QObject::connect(&label[j], SIGNAL(pressSignal(PushButton *)), this ,SLOT(pressSlot(PushButton *)));

		x++;
		if (10 == x)
		{
			y++;
			x = 0;
		}
	}
}

WATCH::~WATCH()
{

}

void WATCH::pressSlot(PushButton * p)
{
	if( now != NULL && p != now && ((p->text() == now->text())))
	{
		int i = 0;
		qsrand(QTime::currentTime().msec() + QTime::currentTime().second() * 1000);
		i = (qrand() + i) % 10;
	
		p->setIcon(icon[i]);
		p->setText(QString::number(i));

		qsrand(QTime::currentTime().msec() + QTime::currentTime().second() * 1000);
		i = (qrand() + i) % 10;
		now->setIcon(icon[i]);
		now->setText(QString::number(i));


		p = NULL;
		now = NULL;

		score++;
		this->statusBar()->showMessage("Your Score Is " + QString::number(score));
	}
	else
	{
		now = p;
	}
}
