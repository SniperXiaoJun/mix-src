/* ====================================================================
* File: UAPField.h
* Created: 11/11/08
* Author:	���� 
* Description : ��Ϣ�ֶ�������
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
		EFIELD_TYPE_ERROR	= 0,		//:: �ֶ����ʹ���
		EACCESS_VIOLATION,				//:: ����Խ��
		EFIELD_ERROR					//:: �ֶδ���
	};									//:: �쳣ö������
	
public:
	
	/**
	* function CUAPException()
	* 
	* discussion: ���캯�� 
	*/
	CUAPException(void){};
	
	/**
	* function CUAPException()
	* 
	* discussion: ���캯�� 
	* @param: aErrType �쳣����
	*/
	CUAPException(TExceptType errType)
	{
		m_eErrCode = errType;
	};
	
	/**
	* function ~CUAPException()
	* 
	* discussion: �������� 
	*/
	virtual ~CUAPException(void){};
	
	/**
	* function GetErrCode()
	* 
	* discussion: ��ȡ�쳣���� 
	* @result: �쳣����
	*/
	TExceptType GetErrCode(void)
	{
		return m_eErrCode;
	};
	
private:
	
	TExceptType m_eErrCode;					//:: �쳣����	
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
	* discussion: ���캯�� 
	* @param: aName ��Ҫ���õ��ֶ�����
	*/
	CUAPField(int iName);
	
	/**
	* function CUAPField()
	* 
	* discussion: ���캯�� 
	* @param: aRhs �����Ķ���
	*/
	CUAPField(const CUAPField &rhs);
	
	/**
	* function CUAPField()
	* 
	* discussion: �������� 
	*/
	virtual ~CUAPField(void);
	
	/**
	* function operator =()
	* 
	* discussion: = ���������� 
	* @param: aRhs ��ֵ�Ķ���
	* @result: ����ֵ�Ķ���
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
	* discussion: �����ֶ����� 
	* @param: aValue ��Ҫ���õ����ݵ��ֽ���ָ��
	* @param: aLen ��Ҫ���õ����ݵ��ֽ���ָ��
	* @result: ���óɹ������
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
	* discussion: �����ֶ����� 
	* @param: aName ��Ҫ���õ��ֶ�����
	* @result: ���óɹ������
	*/
	inline bool SetName(int iName);
	
	/**
	* function GetValue()
	* 
	* discussion: ��ȡ�ֶ����� 
	* @result: �ֶε����ݵ��ֽ���ָ��
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
	* discussion: ��ȡ�ֶ������ֽ������� 
	* @result: �ֶε����ݵ��ֽ�������
	*/
	inline UInt32 GetLength(void) const;
	
	/**
	* function GetName()
	* 
	* discussion: ��ȡ�ֶ����� 
	* @result: �ֶ�����
	*/
	inline int GetName(void) const;

	/**
	* function GetType()
	* 
	* discussion: ��ȡ�ֶ����� 
	* @result: �ֶ�����
	*/
	inline UInt32 GetType(void) const;

protected:

	bool SetBEValue(const Byte *pValue, UInt32 ulLen);
	
protected:
	
	int m_iName;							//:: �ֶ�����
	UInt32 m_ulType;							//:: �ֶ���������

	__int64 m_i64Value;						//::  64λ����			
	UInt64 m_u64Value;							//::  64λ�޷�������
	long m_lValue;							//::  ������
	UInt32 m_ulValue;							//::  32λ�޷�������
    short m_sValue;							//::  ������
    UInt16 m_usValue;							//::  16λ�޷�������
	char m_szValue;							//::  �ַ���
	Byte m_btValue;							//::  �ֽ���
};

#endif // !defined _UAPFIELD_H__
