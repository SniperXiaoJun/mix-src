
#ifndef __MIX_TREE__
#define __MIX_TREE__


#ifdef __cplusplus
extern "C"
{
#endif
	typedef struct _tree_node
	{
		int type;
		int length;
		void * value;
	}tree_node;

	typedef struct _tree
	{
		tree_node * value;
		struct _tree * children;
		struct _tree * brother;
	}tree;

	int tree_init(tree ** tree_root, tree_node * node);

	int tree_uninit(tree ** tree_root);

	int tree_add(tree * tree_root, tree * tree_branch, int tree_pos, int b_is_son);

	int tree_del(tree ** tree_root, tree * tree_branch);

	int tree_member_number(tree * tree_root,int * member_number);

	int tree_print(tree * tree_root);

	int tree_level(tree * tree_root, int * level);

	int tree_level_member_number(tree * tree_root, int level, int * member_number);
#ifdef __cplusplus
}
#endif



#endif /*__MIX_TREE__*/
