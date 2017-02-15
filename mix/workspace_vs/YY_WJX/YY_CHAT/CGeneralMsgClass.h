/*
 * CBankMsg.h
 *
 *  Created on: 2011-9-26
 *      Author: Administrator
 */

#ifndef CGENERALMSGCLASS_H_
#define CGENERALMSGCLASS_H_

#include "UAPMsg.h"
#include "comm.h"

class CGeneralMsgClass: public CUAPMsg
{
public:
    CGeneralMsgClass(const Byte *pValue = NULL, UInt32 ulLen = 0);
    ~CGeneralMsgClass();
    
    int PackMsg(void);
    int ParseMsg(void);
};

#endif /* CGENERALMSGCLASS_H_ */
