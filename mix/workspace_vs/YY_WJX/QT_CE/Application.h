#ifndef APPLICATION_H
#define APPLICATION_H

#include <QApplication>
#include <QWSEvent>
#include <QInputContext>

class Application: public QApplication
{
Q_OBJECT

public:
    Application(int argc, char * argv[]);
    ~Application();

    bool eventFilter(QObject * watched, QEvent * event);

    bool event(QEvent * e);

private:

};

#endif // APPLICATION_H
