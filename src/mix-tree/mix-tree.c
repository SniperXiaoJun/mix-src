
#include "mix-tree.h"
#include "common.h"
#include <stdio.h>
#include <stdlib.h>

int tree_init(tree ** tree_root, tree_node * node)
{
	DEBUG("%s", __FUNCTION__);

	if (NULL == tree_root)
	{
		return -1;
	}

	if (*tree_root)
	{
		tree_uninit(tree_root);
	}

	if (NULL == node)
	{
		*tree_root = NULL;
	}
	else
	{
		(tree *)(*tree_root) = (tree *)malloc(sizeof(tree));

		(tree_node *)(*tree_root)->value = node;

		(tree *)(*tree_root)->brother = NULL;
		(tree *)(*tree_root)->children = NULL;
	}

	return 0;
}

int tree_uninit(tree ** tree_root)
{
	DEBUG("%s", __FUNCTION__);

	if (NULL == tree_root)
	{
		return -1;
	}

	if (*tree_root)
	{
		tree_uninit(&((*tree_root)->brother));
		tree_uninit(&((*tree_root)->children));

		free(*tree_root);
		*tree_root = NULL;
	}
	else
	{
		*tree_root = NULL;
	}

	return 0;
}

int tree_add(tree * tree_root, tree * tree_branch, int tree_pos, int b_is_son)
{
	DEBUG("%s", __FUNCTION__);

	if (NULL == tree_root)
	{
		return -1;
	}

	if (NULL == tree_branch || tree_root == tree_branch)
	{
		// do nothing
	}
	else
	{

		int i = 0;

		if (b_is_son)
		{
			if (tree_root->children)
			{
				tree * tree_target = tree_root->children;

				for (i = 0; i < tree_pos; i++)
				{
					if (tree_target == tree_branch)
					{
						break;
					}

					if (tree_target->brother)
					{
						tree_target = tree_target->brother;
						i++;
					}
					else
					{
						break;
					}
				}

				if (tree_target == tree_branch)
				{
					// do nothing
				}
				else
				{
					tree_target->brother = tree_branch;
				}
			}
			else
			{
				tree_root->children = tree_branch;
			}
		}
		else
		{
			if (tree_root->brother)
			{
				tree * tree_target = tree_root->brother;

				for (i = 0; i < tree_pos; i++)
				{
					if (tree_target == tree_branch)
					{
						break;
					}

					if (tree_target->brother)
					{
						tree_target = tree_target->brother;
						i++;
					}
					else
					{
						break;
					}
				}

				if (tree_target == tree_branch)
				{
					// do nothing
				}
				else
				{
					tree_target->brother = tree_branch;
				}
			}
			else
			{
				tree_root->brother = tree_branch;
			}
		}
	}

	return 0;
}

int tree_del(tree ** tree_root, tree * tree_branch)
{
	DEBUG("%s", __FUNCTION__);

	if (NULL == tree_root)
	{
		return -1;
	}

	if (NULL == *tree_root)
	{
		return 0;
	}

	if (NULL == tree_branch)
	{
		return 0;
	}

	if (*tree_root == tree_branch)
	{
		*tree_root = NULL;
	}
	else
	{
		tree_del(&((*tree_root)->brother), tree_branch);
		tree_del(&((*tree_root)->children), tree_branch);
	}
	
	return 0;
}

int tree_member_number(tree * tree_root,int * member_number)
{
	DEBUG("%s", __FUNCTION__);

	if (tree_root)
	{
		*member_number += 1;
		tree_member_number(tree_root->brother, member_number);
		tree_member_number(tree_root->children, member_number);
	}


	return 0;
}

int tree_print(tree * tree_root)
{
	DEBUG("%s", __FUNCTION__);

	if (tree_root)
	{
		DEBUG("%c", *(char *)(tree_root->value->value));

		tree_print(tree_root->brother);

		tree_print(tree_root->children);
	}

	return 0;
}

int tree_level(tree * tree_root, int * level)
{
	DEBUG("%s", __FUNCTION__);

	return 0;
}

int tree_level_member_number(tree * tree_root, int level, int * member_number)
{
	DEBUG("%s", __FUNCTION__);

	return 0;
}

