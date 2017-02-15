#include <QtGui/QApplication>
#include <QWidget>
#include <QLabel>
#include <QPixmap>
#include <QPropertyAnimation>
#include <QSequentialAnimationGroup>
#include <QParallelAnimationGroup>

int main(int argc,char *argv[]){
	QApplication app(argc,argv);
	QWidget *w=new QWidget();


	w->resize(300,400);
	QPixmap birdimg=QPixmap("1.png").scaled(40,40);
	QLabel *bird_1=new QLabel(w);
	bird_1->setPixmap(birdimg);
	QPropertyAnimation *anim1=new QPropertyAnimation(bird_1, "pos");
	anim1->setDuration(2000);
	anim1->setStartValue(QPoint(0, 360));
	anim1->setEndValue(QPoint(110, 180));
	anim1->setEasingCurve(QEasingCurve::OutBounce);
	//anim1->start();
	QLabel *bird_2=new QLabel(w);
	bird_2->setPixmap(birdimg);
	QPropertyAnimation *anim2=new QPropertyAnimation(bird_2, "pos");
	anim2->setDuration(2000);
	anim2->setStartValue(QPoint(0, 0));
	anim2->setEndValue(QPoint(150, 180));
	anim2->setEasingCurve(QEasingCurve::OutBounce);
	QSequentialAnimationGroup group;
	//QParallelAnimationGroup group;
	group.addAnimation(anim1);
	group.addAnimation(anim2);
	group.start();
	bird_1->move(-40,-40);
	bird_2->move(-40,-40);
	w->show();
	return app.exec();
}
