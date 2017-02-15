#include <QtGui/QApplication>
#include "mainwindow.h"

#include <QFile>
#include <QTextStream>
#include <QDomElement>
#include <QDomDocument>
#include <QDomProcessingInstruction>
#include <QDebug>

//#define CONFIG_IP_ADDRESS_REMOTE "124.205.50.71"
//#define CONFIG_SAVE_SENT "1"
//#define CONFIG_UPDATE_ONLINE "http://www.baidu.com/"

#include "CConfigXML.h"

int fun_xml_write()
{
    if(QFile("info.xml").exists())
    {
        return 0;
    }

    QDomDocument doc;

    QDomProcessingInstruction instruction = doc.createProcessingInstruction("xml","version=\"1.0\" encoding=\"UTF-8\"");

    doc.appendChild(instruction);

    QDomElement root = doc.createElement("Notes");

    doc.appendChild(root);

    QDomElement note = doc.createElement("note");

    root.appendChild(note);

    QDomElement ip_address_remote = doc.createElement("ip_address_remote");

    note.appendChild(ip_address_remote);

    QDomText ip_address_remote_text = doc.createTextNode(CONFIG_IP_ADDRESS_REMOTE);

    ip_address_remote.appendChild(ip_address_remote_text);

    QDomElement save_sent = doc.createElement("save_sent");

    note.appendChild(save_sent);

    QDomText save_sent_text = doc.createTextNode(CONFIG_SAVE_SENT);

    save_sent.appendChild(save_sent_text);

    QDomElement update_online = doc.createElement("update_online");

    note.appendChild(update_online);

    QDomText update_online_text = doc.createTextNode(CONFIG_UPDATE_ONLINE);

    update_online.appendChild(update_online_text);

    QFile file_w("info.xml");

    if (!file_w.open(QIODevice::WriteOnly | QIODevice::Truncate |QIODevice::Text))

        return -1;

    QTextStream out(&file_w);

    out.setCodec("UTF-8");

    doc.save(out,4,QDomNode::EncodingFromTextStream);

    file_w.close();

    return 0;
}

int parseAttr(const QDomElement &element)
{
    QString data;

    QDomNode node = element.firstChild();

    while (!node.isNull()) {
        if (node.toElement().tagName() == "note") {//∆•≈‰noteΩ⁄µ„
            parseAttr(node.toElement());
        }
        else if (node.toElement().tagName() == "ip_address_remote") {//∆•≈‰ Ù–‘no
            QDomNode childNode = node.firstChild();

            if (childNode.nodeType() == QDomNode::TextNode) {
                data = childNode.toText().data();
                qDebug(data.toAscii().constData());
            }
        }
        else if (node.toElement().tagName() == "save_sent") //∆•≈‰ Ù–‘name
        {
            QDomNode childNode = node.firstChild();

            if (childNode.nodeType() == QDomNode::TextNode) {
                data = childNode.toText().data();
                qDebug(data.toAscii().constData());
            }
        }
        else if (node.toElement().tagName() == "update_online") //∆•≈‰ Ù–‘name
        {
            QDomNode childNode = node.firstChild();

            if (childNode.nodeType() == QDomNode::TextNode) {
                data = childNode.toText().data();
                qDebug(data.toAscii().constData());
            }
        }
        node = node.nextSibling();//∂¡»°–÷µ‹Ω⁄µ„
    }

    return 0;
}

int parse_updateAttr(const QDomElement &element)
{
    QString data;

    QDomNode node = element.firstChild();

    while (!node.isNull()) {
        if (node.toElement().tagName() == "note") {//∆•≈‰noteΩ⁄µ„
            parseAttr(node.toElement());
        }
        else if (node.toElement().tagName() == "ip_address_remote") {//∆•≈‰ Ù–‘no
            QDomNode childNode = node.firstChild();

            if (childNode.nodeType() == QDomNode::TextNode) {
                data = childNode.toText().data();
                qDebug(data.toAscii().constData());
            }
        }
        else if (node.toElement().tagName() == "save_sent") //∆•≈‰ Ù–‘name
        {
            QDomNode childNode = node.firstChild();

            if (childNode.nodeType() == QDomNode::TextNode) {
                data = childNode.toText().data();

                if(data == QString("1"))
                {
                    childNode.setNodeValue("0");
                }
                else
                {
                    childNode.setNodeValue("1");
                }
                qDebug(data.toAscii().constData());
            }
        }
        else if (node.toElement().tagName() == "update_online") //∆•≈‰ Ù–‘name
        {
            QDomNode childNode = node.firstChild();

            if (childNode.nodeType() == QDomNode::TextNode) {
                data = childNode.toText().data();
                qDebug(data.toAscii().constData());
            }
        }
        node = node.nextSibling();//∂¡»°–÷µ‹Ω⁄µ„
    }

    return 0;
}

int fun_xml_read()
{
    QString xmlPath = "info.xml";
    QFile file_r(xmlPath);
    if (!file_r.open(QFile::ReadOnly | QFile::Text))
        return -1;
    QString errorStr;
    int errorLine;
    int errorColumn;
    QDomDocument doc_r;
    if (!doc_r.setContent(&file_r, false, &errorStr, &errorLine, &errorColumn))
        return -1;
    file_r.close();

    QDomElement root = doc_r.documentElement();

    return parseAttr(root);
}

int fun_xml_update()
{
    QString xmlPath = "info.xml";
    QFile file_r(xmlPath);
    if (!file_r.open(QFile::ReadOnly | QFile::Text))
        return -1;
    QString errorStr;
    int errorLine;
    int errorColumn;
    QDomDocument doc_r;
    if (!doc_r.setContent(&file_r, false, &errorStr, &errorLine, &errorColumn))
        return -1;
    file_r.close();

    QDomElement root = doc_r.documentElement();

    parse_updateAttr(root);

    QFile file_w("info.xml");

    if (!file_w.open(QIODevice::WriteOnly | QIODevice::Truncate |QIODevice::Text))

        return -1;

    QTextStream out(&file_w);

    out.setCodec("UTF-8");

    root.save(out,3);

    file_w.close();

    return 0;
}

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    w.show();

    CConfigXML::Fun_xml_write();
    CConfigXML::Fun_xml_read();
    CConfigXML::Fun_xml_update();
    CConfigXML::Fun_xml_read();

    int port = CConfigXML::GetPortRemote().toInt();

    qDebug(CConfigXML::GetPortRemote().toAscii().constData());
    
    return a.exec();
}
