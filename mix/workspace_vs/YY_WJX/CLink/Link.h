

typedef struct _sTradeContent			//jiaoyi neirong
{
	char szSelfACC[64];					//�Լ��˺�
	char szKind[64];					//����
	char szMoney[32];					//���
	char szOPPACC[64];					//�Է��˺�
	char szTime[128];					//����ʱ��
}sTradeContent;

typedef struct _sNode
{
	sTradeContent data;
	struct _sNode * m_pNext;
	struct _sNode * m_pBack;
}sNode;


class CLink
{
public:
	CLink(void);
	~CLink(void);
	
	sNode * At(int pos = 0);
	sNode * Next();
	sNode * Previous();
	int TotalNumber();
	int Add(sNode * node);

	int Del(sNode * node);
	int Del(int pos);

	int Update(sNode * from, sNode * to);
	int Update(int pos, sNode * to);

	sNode * Select(sNode * value);

private:
	int m_iTotal;
	sNode * m_pCurrent;
	sNode * m_pHead;
	sNode * m_pTail;
};