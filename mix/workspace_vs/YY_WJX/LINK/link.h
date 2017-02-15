
typedef struct _sTradeContent		//jiaoyi neirong
{
	char szSelfACC[64];					//自己账号
	char szKind[64];					//类型
	char szMoney[32];					//金额
	char szOPPACC[64];					//对方账号
	char szTime[128];					//交易时间
	
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