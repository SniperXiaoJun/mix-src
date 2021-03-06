// 下列 ifdef 块是创建使从 DLL 导出更简单的
// 宏的标准方法。此 DLL 中的所有文件都是用命令行上定义的 NETWORK_EXPORTS
// 符号编译的。在使用此 DLL 的
// 任何其他项目上不应定义此符号。这样，源文件中包含此文件的任何其他项目都会将
// NETWORK_API 函数视为是从 DLL 导入的，而此 DLL 则将用此宏定义的
// 符号视为是被导出的。

#ifdef NETWORKCEDLL_EXPORTS
#define NETWORK_API __declspec(dllexport)
#else
#define NETWORK_API __declspec(dllimport)
#endif


#ifndef NETWORK_H
#define NETWORK_H

#include "..\transaction\IReceiveCallBack.h"
#include "..\transaction\ISendData.h"
#include "..\transaction\IReceiveData.h"

#include <winsock2.h>

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
	void ReceiveUDP(char *pData, int iDataLen, char * strIP, UINT uiPort);

	SOCKET m_sock;
	SOCKADDR_IN m_sockAddr;
private:
	HANDLE m_pThread;
	IReceiveCallBack *m_pNetworkCallback;
	Byte *m_pRecvData;
	Int32 m_iError;
	Int32 m_iRecvLen;
	char m_strAddr[16];
	UInt16 m_usLocalPort;
	UInt16 m_usSendPort;
	Bool m_bflag;
};

#endif // NETWORK_H
