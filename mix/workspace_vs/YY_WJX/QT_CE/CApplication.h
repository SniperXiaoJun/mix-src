#ifndef CAPPLICATION_H
#define CAPPLICATION_H
#include <QInputContext>
#include <QApplication>

class CApplication : public QApplication
{
	Q_OBJECT

public:
	CApplication(int argc, char * argv[]);
	~CApplication();


	bool eventFilter(QObject * watched, QEvent * event);

	bool event(QEvent * e);

private:

};

#endif // CAPPLICATION_H
