#include "CConfigXML.h"

QString CConfigXML::str_ip_address;
QString CConfigXML::str_save_sent;
QString CConfigXML::str_update_online;
QString CConfigXML::str_port;

CConfigXML::CConfigXML()
{
}

int CConfigXML::Fun_xml_read()
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

    return ParseAttr(root);
}

int CConfigXML::Fun_xml_write()
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
    
    QDomElement port_remote = doc.createElement("port_remote");

    note.appendChild(port_remote);

    QDomText port_remote_text = doc.createTextNode(CONFIG_PORT_REMOTE);

    port_remote.appendChild(port_remote_text);

    QFile file_w("info.xml");

    if (!file_w.open(QIODevice::WriteOnly | QIODevice::Truncate |QIODevice::Text))

        return -1;

    QTextStream out(&file_w);

    out.setCodec("UTF-8");

    doc.save(out,4,QDomNode::EncodingFromTextStream);

    file_w.close();

    return 0;
}

int CConfigXML::Fun_xml_update()
{
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

    QString save_sent_string;

    if(str_save_sent == "1")
    {
        save_sent_string = "0";
    }
    else
    {
        save_sent_string = "1";
    }

    QDomText save_sent_text = doc.createTextNode(save_sent_string);

    save_sent.appendChild(save_sent_text);

    QDomElement update_online = doc.createElement("update_online");

    note.appendChild(update_online);

    QDomText update_online_text = doc.createTextNode(CONFIG_UPDATE_ONLINE);

    update_online.appendChild(update_online_text);
    
    QDomElement port_remote = doc.createElement("port_remote");

    note.appendChild(port_remote);

    QDomText port_remote_text = doc.createTextNode(CONFIG_PORT_REMOTE);

    port_remote.appendChild(port_remote_text);

    QFile file_w("info.xml");

    if (!file_w.open(QIODevice::WriteOnly | QIODevice::Truncate |QIODevice::Text))

        return -1;

    QTextStream out(&file_w);

    out.setCodec("UTF-8");

    doc.save(out,4,QDomNode::EncodingFromTextStream);

    file_w.close();

    return 0;
}

QString CConfigXML::GetIPAddress()
{
    return str_ip_address;
}

QString CConfigXML::GetSaveSent()
{
    return str_save_sent;
}

QString CConfigXML::GetUpdateOnline()
{
    return str_update_online;
}

QString CConfigXML::GetPortRemote()
{
    return str_port;
}

int CConfigXML::ParseAttr(const QDomElement &element)
{
    QString data;

    QDomNode node = element.firstChild();

    while (!node.isNull()) {
        if (node.toElement().tagName() == "note") {//∆•≈‰noteΩ⁄µ„
            ParseAttr(node.toElement());
        }
        else if (node.toElement().tagName() == "ip_address_remote") {//∆•≈‰ Ù–‘no
            QDomNode childNode = node.firstChild();

            if (childNode.nodeType() == QDomNode::TextNode) {
                data = childNode.toText().data();
                str_ip_address = data;
                qDebug(data.toAscii().constData());
            }
        }
        else if (node.toElement().tagName() == "save_sent") //∆•≈‰ Ù–‘name
        {
            QDomNode childNode = node.firstChild();

            if (childNode.nodeType() == QDomNode::TextNode) {
                data = childNode.toText().data();
                str_save_sent = data;
                qDebug(data.toAscii().constData());
            }
        }
        else if (node.toElement().tagName() == "update_online") //∆•≈‰ Ù–‘name
        {
            QDomNode childNode = node.firstChild();

            if (childNode.nodeType() == QDomNode::TextNode) {
                data = childNode.toText().data();
                str_update_online = data;
                qDebug(data.toAscii().constData());
            }
        }
        else if (node.toElement().tagName() == "port_remote") //∆•≈‰ Ù–‘name
        {
            QDomNode childNode = node.firstChild();

            if (childNode.nodeType() == QDomNode::TextNode) {
                data = childNode.toText().data();
                str_port = data;
                qDebug(data.toAscii().constData());
            }
        }
        node = node.nextSibling();//∂¡»°–÷µ‹Ω⁄µ„
    }

    return 0;
}
