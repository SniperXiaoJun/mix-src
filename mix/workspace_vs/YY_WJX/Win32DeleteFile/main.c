
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <io.h>

typedef int bool;

bool is_special_dir(const char *path)
{
	return strcmp(path, "..") == 0 || strcmp(path, ".") == 0;
}

//判断文件属性是目录还是文件
bool is_dir(int attrib)
{
	return attrib == 16 || attrib == 18 || attrib == 20;
}

void show_error(const char *file_name)
{
	errno_t err;
	_get_errno(&err);

	switch(err)
	{
		//case ENOTEMPTY:
		//	printf("Given path is not a directory, the directory is not empty, or the directory is either the current working directory or the root directory.\n");
		//	break;
		//case ENOENT:
		//	printf("Path is invalid.\n");
		//	break;
		//case EACCES: 
		//	printf("%s had been opend by some application, can't delete.\n", file_name);
		//	break;
	default:
		printf("%s can't delete.\n", file_name);
	}
}


void get_file_path(const char *path, const char *file_name, char *file_path)
{
	strcpy_s(file_path, sizeof(char) * _MAX_PATH, path);
	file_path[strlen(file_path) - 1] = '\0';
	strcat_s(file_path, sizeof(char) * _MAX_PATH, file_name);
	strcat_s(file_path, sizeof(char) * _MAX_PATH, "\\*");
}
//递归搜索目录中文件并删除
void delete_file(char *path, char *type)
{
	struct _finddata_t dir_info;

	struct _finddata_t file_info;

	intptr_t f_handle;
	char tmp_path[_MAX_PATH];

	if((f_handle = _findfirst(path, &dir_info)) != -1)
	{
		while(_findnext(f_handle, &file_info) == 0)
		{
			if(is_special_dir(file_info.name))
				continue;

			if(is_dir(file_info.attrib))//如果是目录，生成完整的路径
			{ 
				get_file_path(path, file_info.name, tmp_path);
				delete_file(tmp_path ,type);//开始递归删除目录中的内容
				tmp_path[strlen(tmp_path) - 2] = '\0';

				if(file_info.attrib == 20)
					printf("This is system file, can't delete!\n");
				else
				{
					//删除空目录，必须在递归返回前调用_findclose,否则无法删除目录
					if(_rmdir(tmp_path) == -1)
					{
						show_error(tmp_path);//目录非空则会显示出错原因
					}
				}
			}
			else
			{
				strcpy_s(tmp_path, sizeof(char) * _MAX_PATH, path);
				tmp_path[strlen(tmp_path) - 1] = '\0';
				strcat_s(tmp_path, sizeof(char) * _MAX_PATH, file_info.name);//生成完整的文件路径


				if(strstr(tmp_path, type))//判断类型是否一致
				{
					if(remove(tmp_path) == -1)
					{
						show_error(tmp_path);//目录非空则会显示出错原因
					}
				}
			}
		}
		_findclose(f_handle);//关闭打开的文件句柄，并释放关联资源，否则无法删除空目录
	}
	else
	{
		show_error(path);//目录非空则会显示出错原因
	}
}

int main(int argc, char **argv)
{
	char * path = "c:\\data\\*";
	char * type = ".txt";

	//delete_file(path ,type);

	remove("c:\\data\\*.txt");

	system("pause");

	return 0;
}
