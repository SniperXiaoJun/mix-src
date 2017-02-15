#ifndef PUSHBUTTON_H
#define PUSHBUTTON_H

#include <QPushButton>

class PushButton : public QPushButton
{
	Q_OBJECT

public:
	PushButton(QWidget *parent = NULL);
	~PushButton();

protected:
	void mousePressEvent(QMouseEvent * event);
signals:
	void pressSignal(PushButton * );

private:
	
};

#endif // PUSHBUTTON_H
