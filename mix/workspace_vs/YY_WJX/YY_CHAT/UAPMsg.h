/* ====================================================================
* File: UAPMsg.h
* Created: 11/11/08
* Author:	张文 
* Description : 消息类声明
* Version: 1.0
* Copyright (c): Taiji Lab, All rights reserved
* ==================================================================== */
//-------------------------------------------------------------------------------------
// 修改记录: 
// 修 改 人: 闫海成
// 修改日期:2010/08/25
// 修改目的: 添加GetFieldNumber接口的一个重载，添加CreateField()接口
//-------------------------------------------------------------------------------------

#ifndef _UAPMSG_H__
#define _UAPMSG_H__

#define _CRT_SECURE_NO_DEPRECATE

#include <vector>
using std::vector;
#include <map>
using std::map;

#include "IUAPMsg.h"
#include "UAPField.h"

class /*__declspec(dllexport)*//*UAPMSGDLL_API*/ CUAPMsg : public IUAPMsg, public CUAPField
{
public:
	
	/**
	* function CUAPMsg()
	* 
	* discussion: 构造函数 
	*/
	CUAPMsg(int iName = 0);
	
	/**
	* function CUAPMsg()
	* 
	* discussion: 构造函数 
	*/
	CUAPMsg(const Byte *pValue, UInt32 ulLen, int iName = 0);
	
	/**
	* function CUAPMsg()
	* 
	* discussion: 构造函数 
	* @param: rhs 拷贝的对象
	*/
	CUAPMsg(const CUAPMsg &rhs);

	/**
	* function ~CUAPMsg()
	* 
	* discussion: 析构函数 
	*/
	virtual ~CUAPMsg(void);
	
	/**
	* function AddField()
	* 
	* discussion: 添加字段，可添加多个相同字段 
	* @param: aField 添加的字段对象
	* @result: 添加成功与否标识
	*/
	virtual bool AddField(const CUAPField &field);
	
	/**
	* function GetFieldNumber()
	* 
	* discussion: 获取字段数目 
	* @result: 字段数目
	*/
	virtual UInt32 GetFieldNumber(void) const;
	virtual UInt32 GetFieldNumber(int iName) const;
	
	/**
	* function CheckField()
	* 
	* discussion: 检查字段是否为空 
	* @param: aName 检查的字段名称
	* @param: aPos 检查的字段编号
	* @result: 字段是否为空标志
	*/
	virtual bool CheckField(int iName);
	
	/**
	* function GetField()
	* 
	* discussion: 获取字段，如有多个相同字段，默认返回第一个字段，访问非法字段，抛出异常 
	* @param: aName 访问的字段名称
	* @param: aPos 访问的字段编号
	* @result: 字段对象指针
	*/
	virtual const CUAPField &GetField(int iName, UInt32 ulPos = 0) const;
	
	/**
	* function DelField()
	* 
	* discussion: 删除字段，如有多个相同字段，默认删除第一个字段 
	* @param: aName 删除的字段名称
	* @param: aPos 删除的字段编号
	* @result: 删除成功与否标识
	*/
	virtual bool DelField(int iName, UInt32 ulPos = 0);

	virtual bool DelFieldAll();
	
	/**
	* function ModField()
	* 
	* discussion: 修改字段，如有多个相同字段，默认修改第一个字段 
	* @param: aName 修改的字段内容
	* @param: aPos 修改的字段编号
	* @result: 修改成功与否标识
	*/
	virtual bool ModField(const CUAPField &strField, UInt32 ulPos = 0);
	
	/**
	* function PackMsg()
	* 
	* discussion: 打包消息 
	* @result: 打包消息成功与否标识
	*/
	virtual int PackMsg(void) = 0;
	
	/**
	* function ParseMsg()
	* 
	* discussion: 解析消息 
	* @result: 解析消息成功与否标识
	*/
	virtual int ParseMsg(void) = 0;
	
	/**
	* function GetMsgText()
	* 
	* discussion: 获取消息字节流 
	* @result: 消息字节流指针
	*/
	virtual const Byte *GetMsgText(void) const;
	
	/**
	* function GetMsgLen()
	* 
	* discussion: 获取消息字节流长度 
	* @result: 消息字节流长度
	*/
	virtual UInt32 GetMsgLen(void) const;	

	/**
	* function CreateField()
	* 
	* discussion: 创建Field 
	* @result: 产生的Field
	*/
	virtual CUAPField *CreateField(const CUAPField &field);
	
protected:
	
	/**
	* function operator [] ()
	* 
	* discussion: [] 操作符重载，访问非法编号，抛出异常 
	* @param: aNum 访问的字段编号
	* @result: 字段对象指针
	*/
	virtual const CUAPField &operator [] (UInt32 ulNum) const;
	
protected:
	
	vector<CUAPField *> m_vecMsgEntity;			//:: 消息字段指针向量
	UInt32 m_ulFieldPos;							//:: 消息字段位置
	map<string, UInt32> m_mapNamePos;				//:: 消息字段名映射
	map<int, UInt32> m_mapNameNum;				//:: 消息字段名个数	
};
	
#endif // !defined _UAPMSG_H__
