/*
 * Arg.h
 *
 *  Created on: 2011-6-10
 *      Author: Ice Lee
 */

#ifndef ARG_H_
#define ARG_H_
#include "common.h"

#define ARG_NUM		4

class CArg
	{
public:
	CArg();
	~CArg();
	
	Int32 SetType(Int32 iType);
	Int32 GetType();
	Int32 SetCode(Int32 iCode);
	Int32 GetCode();
	Int32 SetIndex(Int32 iIndex);
	Int32 GetIndex();
	Int32 SetPointer(Int32 iNum, void* pPointer);
	void* GetPointer(Int32 iNum);
	Int32 SetLength(Int32 iNum, Int32 iLen);
	Int32 GetLength(Int32 iNum);
private:
	Int32 m_iType;
	Int32 m_iCode;
	Int32 m_iIndex;
	void* m_pPointer[ARG_NUM];
	UInt32 m_uiLength[ARG_NUM];
	};


#endif /* MSARG_H_ */
