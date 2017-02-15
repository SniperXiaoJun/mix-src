#include "pushbutton.h"

PushButton::PushButton(QWidget *parent)
	: QPushButton(parent)
{

}

PushButton::~PushButton()
{

}

void PushButton::mousePressEvent(class QMouseEvent *event)
{
	emit pressSignal(this);
}
