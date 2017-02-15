/*
 * comm.h
 *
 *  Created on: 2011-9-26
 *      Author: Administrator
 */

#ifndef COMM_H_
#define COMM_H_

#include <QString>

#include <QTreeWidgetItem>

#define EMT_SUCCESS 0x00000000
#define EMT_ERROR   0xFFFFFFFF

class CChatDialog;

typedef struct _SYY_CHAT_USR
{
	QString strIP;
	QString strName;
	QString strNote;
	QTreeWidgetItem * pTreeWidgetItem;
	CChatDialog * pChatDialog;
	
}SYY_CHAT_USR;

enum EFIELD_NAME_USR
{
	USR_LOGIN,
	USR_LOGOUT,
	USR_MSG,
    USR_NAME,
	USR_COMMENT,
    EFIELD_NAME_USR_COUNT
};

typedef struct _SGeneralMsgStruct
{
    unsigned int name :4;
    unsigned int length :28;
} SGeneralMsgStruct;


#endif /* COMM_H_ */
