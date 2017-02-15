/* ====================================================================
* File: IUAPMsg.h
* Created: 11/11/08
* Author:	���� 
* Description : ��Ϣ�ӿ�������
* Version: 1.0
* Copyright (c): Taiji Lab, All rights reserved
* ==================================================================== */
//-------------------------------------------------------------------------------------
// �޸ļ�¼: 
// �� �� ��: �ƺ���
// �޸�����:2010/08/25
// �޸�Ŀ��: ���GetFieldNumber�ӿڵ�һ�����أ����CreateField()�ӿ�
//-------------------------------------------------------------------------------------


#ifndef _IUAPMSG_H__
#define _IUAPMSG_H__

#include "UAPField.h"

class IUAPMsg
{
public:
	
	/**
	* function AddField()
	* 
	* discussion: ����ֶΣ�����Ӷ����ͬ�ֶ� 
	* @param: aField ��ӵ��ֶζ���
	* @result: ��ӳɹ�����ʶ
	*/
	virtual bool AddField(const CUAPField &field) = 0;
	
	/**
	* function GetFieldNumber()
	* 
	* discussion: ��ȡ�ֶ���Ŀ 
	* @result: �ֶ���Ŀ
	*/
	virtual UInt32 GetFieldNumber(void) const = 0;
	virtual UInt32 GetFieldNumber(int iName) const = 0;
	
	/**
	* function CheckField()
	* 
	* discussion: ����ֶ��Ƿ�Ϊ�� 
	* @param: aName �����ֶ�����
	* @param: aPos �����ֶα��
	* @result: �ֶ��Ƿ�Ϊ�ձ�־
	*/
	virtual bool CheckField(int iName) = 0;
	
	/**
	* function GetField()
	* 
	* discussion: ��ȡ�ֶΣ����ж����ͬ�ֶΣ�Ĭ�Ϸ��ص�һ���ֶΣ����ʷǷ��ֶΣ��׳��쳣 
	* @param: aName ���ʵ��ֶ�����
	* @param: aPos ���ʵ��ֶα��
	* @result: �ֶζ���ָ��
	*/
	virtual const CUAPField &GetField(int iName, UInt32 ulPos = 0) const = 0;
	
	/**
	* function DelField()
	* 
	* discussion: ɾ���ֶΣ����ж����ͬ�ֶΣ�Ĭ��ɾ����һ���ֶ� 
	* @param: aName ɾ�����ֶ�����
	* @param: aPos ɾ�����ֶα��
	* @result: ɾ���ɹ�����ʶ
	*/
	virtual bool DelField(int iName, UInt32 ulPos = 0) = 0;

	virtual bool DelFieldAll() = 0;
	
	/**
	* function ModField()
	* 
	* discussion: �޸��ֶΣ����ж����ͬ�ֶΣ�Ĭ���޸ĵ�һ���ֶ� 
	* @param: aName �޸ĵ��ֶ�����
	* @param: aPos �޸ĵ��ֶα��
	* @result: �޸ĳɹ�����ʶ
	*/
	virtual bool ModField(const CUAPField &field, UInt32 ulPos = 0) = 0;
	
	/**
	* function PackMsg()
	* 
	* discussion: �����Ϣ 
	* @result: �����Ϣ�ɹ�����ʶ
	*/
	virtual int PackMsg(void) = 0;
	
	/**
	* function ParseMsg()
	* 
	* discussion: ������Ϣ 
	* @result: ������Ϣ�ɹ�����ʶ
	*/
	virtual int ParseMsg(void) = 0;
	
	/**
	* function GetMsgText()
	* 
	* discussion: ��ȡ��Ϣ�ֽ��� 
	* @result: ��Ϣ�ֽ���ָ��
	*/
	virtual const Byte *GetMsgText(void) const = 0;
	
	/**
	* function GetMsgLen()
	* 
	* discussion: ��ȡ��Ϣ�ֽ������� 
	* @result: ��Ϣ�ֽ�������
	*/
	virtual UInt32 GetMsgLen(void) const = 0;	
	/**
	* function CreateField()
	* 
	* discussion: ����Field 
	* @result: ������Field
	*/
	virtual CUAPField *CreateField(const CUAPField &field) = 0;
	
protected:
	
	/**
	* function operator [] ()
	* 
	* discussion: [] ���������أ����ʷǷ���ţ��׳��쳣 
	* @param: aNum ���ʵ��ֶα��
	* @result: �ֶζ���ָ��
	*/
	virtual const CUAPField &operator [] (UInt32 ulNum) const = 0;	
};
	
#endif // !defined _IUAPMSG_H__
