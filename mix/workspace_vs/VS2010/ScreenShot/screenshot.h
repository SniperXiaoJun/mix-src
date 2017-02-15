#ifndef SCREENSHOT_H
#define SCREENSHOT_H

#include <QtGui/QMainWindow>
#include "ui_screenshot.h"

class ScreenShot : public QWidget
{
	Q_OBJECT
public:
	ScreenShot(QWidget *parent = 0);
	~ScreenShot();

private:
	Ui::ScreenShotClass * ui;
};

#endif // SCREENSHOT_H
