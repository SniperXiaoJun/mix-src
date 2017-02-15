
#include <QTcpServer>
#include <QTcpSocket>

class CTcpServer:public QObject
{
	Q_OBJECT
public:
	CTcpServer(void);
	~CTcpServer(void);

	QTcpServer * server;
	QTcpSocket * socket;
	QTcpSocket * socketdd ;


	public slots:
		void getConnect();
		void Read();
};
