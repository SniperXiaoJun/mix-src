/* ====================================================================
* File: UAPMsg.h
* Created: 11/11/08
* Author:	���� 
* Description : ��Ϣ������
* Version: 1.0
* Copyright (c): Taiji Lab, All rights reserved
* ==================================================================== */
//-------------------------------------------------------------------------------------
// �޸ļ�¼: 
// �� �� ��: �ƺ���
// �޸�����:2010/08/25
// �޸�Ŀ��: ���GetFieldNumber�ӿڵ�һ�����أ����CreateField()�ӿ�
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
	* discussion: ���캯�� 
	*/
	CUAPMsg(int iName = 0);
	
	/**
	* function CUAPMsg()
	* 
	* discussion: ���캯�� 
	*/
	CUAPMsg(const Byte *pValue, UInt32 ulLen, int iName = 0);
	
	/**
	* function CUAPMsg()
	* 
	* discussion: ���캯�� 
	* @param: rhs �����Ķ���
	*/
	CUAPMsg(const CUAPMsg &rhs);

	/**
	* function ~CUAPMsg()
	* 
	* discussion: �������� 
	*/
	virtual ~CUAPMsg(void);
	
	/**
	* function AddField()
	* 
	* discussion: ����ֶΣ�����Ӷ����ͬ�ֶ� 
	* @param: aField ��ӵ��ֶζ���
	* @result: ��ӳɹ�����ʶ
	*/
	virtual bool AddField(const CUAPField &field);
	
	/**
	* function GetFieldNumber()
	* 
	* discussion: ��ȡ�ֶ���Ŀ 
	* @result: �ֶ���Ŀ
	*/
	virtual UInt32 GetFieldNumber(void) const;
	virtual UInt32 GetFieldNumber(int iName) const;
	
	/**
	* function CheckField()
	* 
	* discussion: ����ֶ��Ƿ�Ϊ�� 
	* @param: aName �����ֶ�����
	* @param: aPos �����ֶα��
	* @result: �ֶ��Ƿ�Ϊ�ձ�־
	*/
	virtual bool CheckField(int iName);
	
	/**
	* function GetField()
	* 
	* discussion: ��ȡ�ֶΣ����ж����ͬ�ֶΣ�Ĭ�Ϸ��ص�һ���ֶΣ����ʷǷ��ֶΣ��׳��쳣 
	* @param: aName ���ʵ��ֶ�����
	* @param: aPos ���ʵ��ֶα��
	* @result: �ֶζ���ָ��
	*/
	virtual const CUAPField &GetField(int iName, UInt32 ulPos = 0) const;
	
	/**
	* function DelField()
	* 
	* discussion: ɾ���ֶΣ����ж����ͬ�ֶΣ�Ĭ��ɾ����һ���ֶ� 
	* @param: aName ɾ�����ֶ�����
	* @param: aPos ɾ�����ֶα��
	* @result: ɾ���ɹ�����ʶ
	*/
	virtual bool DelField(int iName, UInt32 ulPos = 0);

	virtual bool DelFieldAll();
	
	/**
	* function ModField()
	* 
	* discussion: �޸��ֶΣ����ж����ͬ�ֶΣ�Ĭ���޸ĵ�һ���ֶ� 
	* @param: aName �޸ĵ��ֶ�����
	* @param: aPos �޸ĵ��ֶα��
	* @result: �޸ĳɹ�����ʶ
	*/
	virtual bool ModField(const CUAPField &strField, UInt32 ulPos = 0);
	
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
	virtual const Byte *GetMsgText(void) const;
	
	/**
	* function GetMsgLen()
	* 
	* discussion: ��ȡ��Ϣ�ֽ������� 
	* @result: ��Ϣ�ֽ�������
	*/
	virtual UInt32 GetMsgLen(void) const;	

	/**
	* function CreateField()
	* 
	* discussion: ����Field 
	* @result: ������Field
	*/
	virtual CUAPField *CreateField(const CUAPField &field);
	
protected:
	
	/**
	* function operator [] ()
	* 
	* discussion: [] ���������أ����ʷǷ���ţ��׳��쳣 
	* @param: aNum ���ʵ��ֶα��
	* @result: �ֶζ���ָ��
	*/
	virtual const CUAPField &operator [] (UInt32 ulNum) const;
	
protected:
	
	vector<CUAPField *> m_vecMsgEntity;			//:: ��Ϣ�ֶ�ָ������
	UInt32 m_ulFieldPos;							//:: ��Ϣ�ֶ�λ��
	map<string, UInt32> m_mapNamePos;				//:: ��Ϣ�ֶ���ӳ��
	map<int, UInt32> m_mapNameNum;				//:: ��Ϣ�ֶ�������	
};
	
#endif // !defined _UAPMSG_H__
