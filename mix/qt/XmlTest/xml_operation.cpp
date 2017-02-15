#include "xml_operation.h"

#include <QFile>
#include <QDomDocument>
#include <QTextStream>

bool xml_create(QString rootNode, QString fileName, QString filePath)
{
    QString xmlFileName = filePath + fileName;

    if(QFile(xmlFileName).exists())
    {
        return false;
    }

    QDomDocument doc;

    QDomProcessingInstruction instruction = doc.createProcessingInstruction("xml","version=\"1.0\" encoding=\"UTF-8\"");

    doc.appendChild(instruction);

    QDomElement root = doc.createElement(rootNode);

    doc.appendChild(root);

    QFile file_w(xmlFileName);

    if (!file_w.open(QIODevice::WriteOnly | QIODevice::Truncate |QIODevice::Text))
    {
         return false;
    }
    else
    {
        QTextStream out(&file_w);

        out.setCodec("UTF-8");

        doc.save(out,4/*TABLE º¸*/,QDomNode::EncodingFromTextStream);

        file_w.close();

        return true;
    }

    return true;
}

bool xml_delete(QString fileName, QString filePath)
{
    QString xmlFileName = filePath + fileName;

    if(!QFile::remove(xmlFileName))
    {
        return true;
    }
    else
    {
        return false;
    }
}

bool xml_node_create(QString nodeName, QString parentNodeName, QString fileName, QString filePath)
{
    QString xmlFileName  = filePath + fileName;

    QFile file_r(xmlFileName);
    if (!file_r.open(QFile::ReadOnly | QFile::Text))
    {
        return false;
    }

    QString errorStr;
    int errorLine;
    int errorColumn;
    QDomDocument doc_r;
    if (!doc_r.setContent(&file_r, false, &errorStr, &errorLine, &errorColumn))
        return false;
    file_r.close();

    QDomElement root = doc_r.documentElement();

    return parseAttr_write(nodeName, parentNodeName, root);

    return false;
}

bool xml_node_delete(QString nodeName, QString parentNodeName, QString fileName, QString filePath)
{
    return false;
}

bool xml_note_write(QString nodeName, QString nodeValue, QString parentNodeName, QString fileName, QString filePath)
{
    return false;
}

bool xml_note_read(QString nodeName, QString &nodeValue, QString parentNodeName, QString fileName, QString filePath)
{
    return false;
}


bool parseAttr_write(QString nodeName, QString parentNodeName, QDomElement &element)
{
    QDomNode node = element.firstChild();

    while (!node.isNull()) {
        if (node.toElement().tagName() == "note") {//∆•≈‰noteΩ⁄µ„
            parseAttr_write(node.toElement());
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
