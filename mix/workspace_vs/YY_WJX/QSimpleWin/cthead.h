#ifndef CTHEAD_H
#define CTHEAD_H

#include <QThead>

class CThead : public QThead
{
	Q_OBJECT

public:
	CThead(QObject *parent);
	~CThead();

	void run();

private:
	int iSpaceMSecond;
};

#endif // CTHEAD_H
