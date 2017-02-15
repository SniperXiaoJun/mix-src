/*
 * CBaseData.h
 *
 *  Created on: 2012-1-13
 *      Author: Administrator
 */

#ifndef CBASEDATA_H_
#define CBASEDATA_H_

class CBaseData
{
public:
    CBaseData();
    virtual ~CBaseData();
    
protected:
    char * iData;
    long long iLen;
};

#endif /* CBASEDATA_H_ */
