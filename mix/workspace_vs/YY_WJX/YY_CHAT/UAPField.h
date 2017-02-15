/* ====================================================================
* File: UAPField.h
* Created: 11/11/08
* Author:	张文 
* Description : 消息字段类声明
* Version: 1.0
* Copyright (c): Taiji Lab, All rights reserved
* ==================================================================== */

#ifndef _UAPFIELD_H__
#define _UAPFIELD_H__

#include "IUAPField.h"
#include "Data.h"

class /*UAPMSGDLL_API*/ CUAPException
{	
public:
	
	enum TExceptType
	{
		EFIELD_TYPE_ERROR	= 0,		//:: 字段类型错误
		EACCESS_VIOLATION,				//:: 访问越界
		EFIELD_ERROR					//:: 字段错误
	};									//:: 异常枚举类型
	
public:
	
	/**
	* function CUAPException()
	* 
	* discussion: 构造函数 
	*/
	CUAPException(void){};
	
	/**
	* function CUAPException()
	* 
	* discussion: 构造函数 
	* @param: aErrType 异常类型
	*/
	CUAPException(TExceptType errType)
	{
		m_eErrCode = errType;
	};
	
	/**
	* function ~CUAPException()
	* 
	* discussion: 析构函数 
	*/
	virtual ~CUAPException(void){};
	
	/**
	* function GetErrCode()
	* 
	* discussion: 获取异常类型 
	* @result: 异常类型
	*/
	TExceptType GetErrCode(void)
	{
		return m_eErrCode;
	};
	
private:
	
	TExceptType m_eErrCode;					//:: 异常类型	
};

class /*__declspec(dllexport)*//*UAPMSGDLL_API*/ CUAPField : public IUAPField, public CData
{
public:
	
	enum
	{   
		ECHAR,
		ESHORT,
		ELONG,
		EINT64,
		EBYTE,
		EU16,
		EU32,
		EU64,
		ESTRING,
		EUFILEDTYPE
	};
	
	/**
	* function CUAPField()
	* 
	* discussion: 构造函数 
	* @param: aName 需要设置的字段名称
	*/
	CUAPField(int iName);
	
	/**
	* function CUAPField()
	* 
	* discussion: 构造函数 
	* @param: aRhs 拷贝的对象
	*/
	CUAPField(const CUAPField &rhs);
	
	/**
	* function CUAPField()
	* 
	* discussion: 析构函数 
	*/
	virtual ~CUAPField(void);
	
	/**
	* function operator =()
	* 
	* discussion: = 操作符重载 
	* @param: aRhs 赋值的对象
	* @result: 被赋值的对象
	*/
	CUAPField &operator = (const CUAPField &rhs);
	CUAPField &operator = (char szValue);
	CUAPField &operator = (short sValue);
	CUAPField &operator = (long lValue);
	CUAPField &operator = (__int64 i64Value);
	CUAPField &operator = (Byte btValue);
	CUAPField &operator = (UInt16 usValue);
	CUAPField &operator = (UInt32 ulValue);
	CUAPField &operator = (UInt64 u64Value);
	CUAPField &operator = (const char *pString);
	CUAPField &operator = (const string &strValue);
	
	/**
	* function SetValue()
	* 
	* discussion: 设置字段数据 
	* @param: aValue 需要设置的数据的字节流指针
	* @param: aLen 需要设置的数据的字节流指针
	* @result: 设置成功与否标记
	*/
	bool SetValue(const Byte *pValue, UInt32 ulLen, UInt32 ulType = EUFILEDTYPE);
	bool SetValue(const char *pString);
	bool SetValue(const string &strValue);
	bool SetValue(char szValue);
	bool SetValue(short sValue);
	bool SetValue(long lValue);
    bool SetValue(__int64 i64Value);
	bool SetValue(Byte btValue);
	bool SetValue(UInt16 usValue);
	bool SetValue(UInt32 ulValue);
	bool SetValue(UInt64 u64Value);

	/**
	* function SetName()
	* 
	* discussion: 设置字段名称 
	* @param: aName 需要设置的字段名称
	* @result: 设置成功与否标记
	*/
	inline bool SetName(int iName);
	
	/**
	* function GetValue()
	* 
	* discussion: 获取字段数据 
	* @result: 字段的数据的字节流指针
	*/
	const Byte *GetValue(void) const;
	const char *GetValueString(void) const;
	char GetValueChar(void) const;
	short GetValueShort(void) const;
	long GetValueLong(void) const;
    __int64 GetValueI64(void) const;
    Byte GetValueByte(void) const;
	UInt16 GetValueU16(void) const;
	UInt32 GetValueU32(void) const;
	UInt64 GetValueU64(void) const;
	
	/**
	* function GetLength()
	* 
	* discussion: 获取字段数据字节流长度 
	* @result: 字段的数据的字节流长度
	*/
	inline UInt32 GetLength(void) const;
	
	/**
	* function GetName()
	* 
	* discussion: 获取字段名称 
	* @result: 字段名称
	*/
	inline int GetName(void) const;

	/**
	* function GetType()
	* 
	* discussion: 获取字段类型 
	* @result: 字段类型
	*/
	inline UInt32 GetType(void) const;

protected:

	bool SetBEValue(const Byte *pValue, UInt32 ulLen);
	
protected:
	
	int m_iName;							//:: 字段名称
	UInt32 m_ulType;							//:: 字段数据类型

	__int64 m_i64Value;						//::  64位整型			
	UInt64 m_u64Value;							//::  64位无符号整型
	long m_lValue;							//::  长整型
	UInt32 m_ulValue;							//::  32位无符号整型
    short m_sValue;							//::  短整型
    UInt16 m_usValue;							//::  16位无符号整型
	char m_szValue;							//::  字符型
	Byte m_btValue;							//::  字节型
};

#endif // !defined _UAPFIELD_H__
