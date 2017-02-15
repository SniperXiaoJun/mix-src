/* ====================================================================
* File: IUAPField.h
* Created: 2010-07-23
* Author:	Zhang Wen 
* Description : 消息字段接口类声明
* Version: 1.0
* Copyright (c): Taiji Lab, All rights reserved
* ==================================================================== */

#ifndef _IUAPFIELD_H__
#define _IUAPFIELD_H__

#include <string>
using std::string;

#include "../Common/common.h"

class IUAPField
{
public:
	
	/**
	* function SetValue()
	* 
	* discussion: 设置字段数据 
	* @param: aValue 需要设置的数据的字节流指针
	* @param: aLen 需要设置的数据的字节流指针
	* @result: 设置成功与否标记
	*/
	virtual bool SetValue(const Byte *pValue, UInt32 ulLen, UInt32 ulType) = 0;
	virtual bool SetValue(const char *pString) = 0;
	virtual bool SetValue(const string &strValue) = 0;
	virtual bool SetValue(char szValue) = 0;
	virtual bool SetValue(short sValue) = 0;
	virtual bool SetValue(long lValue) = 0;
    virtual bool SetValue(__int64 i64Value) = 0;	
	virtual bool SetValue(Byte btValue) = 0;
	virtual bool SetValue(UInt16 usValue) = 0;
	virtual bool SetValue(UInt32 ulValue) = 0;
	virtual bool SetValue(UInt64 u64Value) = 0;

	/**
	* function SetValue()
	* 
	* discussion: 设置字段名称 
	* @param: aName 需要设置的字段名称
	* @result: 设置成功与否标记
	*/
	virtual bool SetName(int iName) = 0;
	
	/**
	* function GetValue()
	* 
	* discussion: 获取字段数据 
	* @result: 字段的数据的字节流指针
	*/
	virtual const Byte *GetValue(void) const = 0;
	virtual const char *GetValueString(void) const = 0;
	virtual char GetValueChar(void) const = 0;
	virtual short GetValueShort(void) const = 0;
	virtual long GetValueLong(void) const = 0;
    virtual __int64 GetValueI64(void) const = 0;
	virtual Byte GetValueByte(void) const = 0;
	virtual UInt16 GetValueU16(void) const = 0;
	virtual UInt32 GetValueU32(void) const = 0;
	virtual UInt64 GetValueU64(void) const = 0;
	
	/**
	* function GetLength()
	* 
	* discussion: 获取字段数据字节流长度 
	* @result: 字段的数据的字节流长度
	*/
	virtual UInt32 GetLength(void) const = 0;
	
	/**
	* function GetName()
	* 
	* discussion: 获取字段名称 
	* @result: 字段名称
	*/
	virtual int GetName(void) const = 0;
	
	/**
	* function GetType()
	* 
	* discussion: 获取字段类型 
	* @result: 字段类型
	*/
	virtual UInt32 GetType(void) const = 0;
};

#endif // !defined _IUAPFIELD_H__
