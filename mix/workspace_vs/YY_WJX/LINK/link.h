
typedef struct _sTradeContent		//jiaoyi neirong
{
	char szSelfACC[64];					//�Լ��˺�
	char szKind[64];					//����
	char szMoney[32];					//���
	char szOPPACC[64];					//�Է��˺�
	char szTime[128];					//����ʱ��
	
}sTradeContent;


typedef struct _Page
{
	int iNumber;
	sTradeContent iContent;
}Page;

typedef struct _Node
{
	struct _Node * next;
	struct _Node * back;
	Page data;
}Node;

typedef struct _Link
{
	int len;
	Node * head;
	Node* tail;
}Link;

Node * FindNode(Link * l, int i);

Link * FreeNode(Link * l);

Link * AddNode(Link * l, Node node);

Link * DelNode(Link * l);