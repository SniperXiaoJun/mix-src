#include "link.h"
#include "stdlib.h"
#include "stdio.h"

Node * FindNode(Link * l, int i)
{
		int j;
	Node * pNode;
	if(i < 0 || i > l->len)
	{
		return NULL;
	}

	pNode = l->head;

	for(j = 0; j < i; j++)
	{
		pNode = pNode->next;
	}
	return pNode;
}

Link * FreeNode(Link * l)
{
	Node * pNode = l->head;
	Node * qNode = NULL;
	int i ;
	for( i = 0; i < l->len; i ++)
	{
		qNode = pNode;
		free( qNode);
		qNode = NULL;
	}
	return NULL;
}

Link * AddNode(Link * l, Node node)
{
	Node * pNode = NULL;
	Node * qNode = NULL;

	if(NULL == l)
	{
		l = malloc(sizeof(Link));
		pNode = malloc(sizeof(Node));
		memcpy(pNode->data, node.data, sizeof(Page));
		pNode->back = NULL;
		pNode->next = NULL;
		l->head = pNode;
		l->tail = pNode;
		l->len = 1;
	}
	return NULL;
}

Link * DelNode(Link * l)
{
	return NULL;
}



int main()
{
	return 0;
}
