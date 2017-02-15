#ifndef CCONFIGXML_H
#define CCONFIGXML_H

#include <QFile>
#include <QTextStream>
#include <QDomElement>
#include <QDomDocument>
#include <QDomProcessingInstruction>
#include <QDebug>
#include <QString>

#define CONFIG_IP_ADDRESS_REMOTE "124.205.50.71"
#define CONFIG_SAVE_SENT "1"
#define CONFIG_UPDATE_ONLINE "http://www.baidu.com/"
#define CONFIG_PORT_REMOTE "8888"

class CConfigXML
{
public:
    CConfigXML();

    static int Fun_xml_read();
    static int Fun_xml_write();
    static int Fun_xml_update();
    static int ParseAttr(const QDomElement &element);

    static QString GetIPAddress();
    static QString GetSaveSent();
    static QString GetUpdateOnline();
    static QString GetPortRemote();

private:
    static QString str_ip_address;
    static QString str_save_sent;
    static QString str_update_online;
    static QString str_port;
};



#endif // CCONFIGXML_H
