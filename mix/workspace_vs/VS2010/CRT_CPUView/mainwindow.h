#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "ui_mainwindow.h"

class MainWindow : public QMainWindow
{
	Q_OBJECT

public:
	MainWindow(QWidget *parent = 0);
	~MainWindow();

	void paintEvent(QPaintEvent*event);

private slots:
	void SlotTimerOut();

private:
	Ui::MainWindow ui;

	QTimer * m_pTimer;
	
};

#endif // MAINWINDOW_H
