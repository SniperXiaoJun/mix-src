// ���� ifdef ���Ǵ���ʹ�� DLL �������򵥵�
// ��ı�׼�������� DLL �е������ļ��������������϶���� NETWORK_EXPORTS
// ���ű���ġ���ʹ�ô� DLL ��
// �κ�������Ŀ�ϲ�Ӧ����˷��š�������Դ�ļ��а������ļ����κ�������Ŀ���Ὣ
// NETWORK_API ������Ϊ�Ǵ� DLL ����ģ����� DLL ���ô˺궨���
// ������Ϊ�Ǳ������ġ�
#ifdef NETWORK_EXPORTS
#define NETWORK_API __declspec(dllexport)
#else
#define NETWORK_API __declspec(dllimport)
#endif


#ifndef NETWORK_H
#define NETWORK_H

#include "..\transaction\IReceiveCallBack.h"
#include "..\transaction\ISendData.h"
#include "..\transaction\IReceiveData.h"
#include <afxsock.h>

class CWinSocket;


enum ConnectType {EUDP, EHTTP};

class NETWORK_API CNetwork : public ISendData, public IReceiveData
{
public:
	CNetwork();
	CNetwork(const Char *pLocalAddr, UInt16 usLocalPort);
	~CNetwork();

	void Open(const Char *pLocalAddr, UInt16 usLocalPort);
	void SetCallback(IReceiveCallBack *pCallback);
	Int32 SendUDP(const Byte *pSendingData, Int32 iSendingSize);
	Bool ReadUDP();
	
	void SetSendPort(UInt16 usSendPort);
	void SetSendAddr(const Char *pHostAddr);

	Int32 SendData(const Byte *pData, Int32 iLen);
	Int32 ReceiveData(IReceiveCallBack *pCallBack);
	void ResetCallBack();

	void SocketError(Int32 uError);
	void ReceiveUDP(char *pData, int iDataLen, CString strIP, UINT uiPort);

private:
	IReceiveCallBack *m_pNetworkCallback;
	CWinSocket  *m_pSocket;
	Byte *m_pRecvData;
	Int32 m_iError;
	Int32 m_iRecvLen;
	CString m_strAddr;
	UInt16 m_usLocalPort;
	UInt16 m_usSendPort;
	Bool m_bflag;
};

#endif // NETWORK_H
