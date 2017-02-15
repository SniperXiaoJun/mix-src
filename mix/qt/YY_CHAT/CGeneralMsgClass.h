/*
 * CBankMsg.h
 *
 *  Created on: 2011-9-26
 *      Author: Administrator
 */

#ifndef CGENERALMSGCLASS_H_
#define CGENERALMSGCLASS_H_

#include "CBaseDataMessage.h"
#include "comm.h"

class CGeneralMsgClass: public CBaseDataMessage
{
public:
    CGeneralMsgClass(const char *pValue = NULL, int ulLen = 0);
    ~CGeneralMsgClass();
    
    int PackMsg(void);
    int ParseMsg(void);
};

#endif /* CGENERALMSGCLASS_H_ */
