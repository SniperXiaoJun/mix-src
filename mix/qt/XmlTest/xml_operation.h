#ifndef XML_OPERATION_H
#define XML_OPERATION_H

#include <QString>
#include <QDomElement>

bool xml_create(QString rootNode = "root", QString fileName = "xml.xml", QString filePath = "");
bool xml_delete(QString fileName = "xml.xml", QString filePath = "");
bool xml_node_create(QString nodeName, QString parentNodeName = "root", QString fileName = "xml.xml", QString filePath = "");
bool xml_node_delete(QString nodeName, QString parentNodeName = "root", QString fileName = "xml.xml", QString filePath = "");
bool xml_note_write(QString nodeName, QString nodeValue, QString parentNodeName = "root", QString fileName = "xml.xml", QString filePath = "");
bool xml_note_read(QString nodeName, QString &nodeValue, QString parentNodeName = "root", QString fileName = "xml.xml", QString filePath = "");

bool parseAttr_write(QString nodeName, QString parentNodeName, QDomElement &element);

#endif // XML_OPERATION_H
