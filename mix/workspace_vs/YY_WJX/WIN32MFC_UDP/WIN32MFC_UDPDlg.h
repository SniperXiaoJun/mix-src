// WIN32MFC_UDPDlg.h : ͷ�ļ�
//

#pragma once

#include "WinSocket.h"

// CWIN32MFC_UDPDlg �Ի���
class CWIN32MFC_UDPDlg : public CDialog
{
// ����
public:
	CWIN32MFC_UDPDlg(CWnd* pParent = NULL);	// ��׼���캯��

// �Ի�������
	enum { IDD = IDD_WIN32MFC_UDP_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��


// ʵ��
protected:
	HICON m_hIcon;

	// ���ɵ���Ϣӳ�亯��
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedCancel();

	CWinSocket m_sock;
};
