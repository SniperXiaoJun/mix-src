
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <io.h>

typedef int bool;

bool is_special_dir(const char *path)
{
	return strcmp(path, "..") == 0 || strcmp(path, ".") == 0;
}

//�ж��ļ�������Ŀ¼�����ļ�
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
//�ݹ�����Ŀ¼���ļ���ɾ��
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

			if(is_dir(file_info.attrib))//�����Ŀ¼������������·��
			{ 
				get_file_path(path, file_info.name, tmp_path);
				delete_file(tmp_path ,type);//��ʼ�ݹ�ɾ��Ŀ¼�е�����
				tmp_path[strlen(tmp_path) - 2] = '\0';

				if(file_info.attrib == 20)
					printf("This is system file, can't delete!\n");
				else
				{
					//ɾ����Ŀ¼�������ڵݹ鷵��ǰ����_findclose,�����޷�ɾ��Ŀ¼
					if(_rmdir(tmp_path) == -1)
					{
						show_error(tmp_path);//Ŀ¼�ǿ������ʾ����ԭ��
					}
				}
			}
			else
			{
				strcpy_s(tmp_path, sizeof(char) * _MAX_PATH, path);
				tmp_path[strlen(tmp_path) - 1] = '\0';
				strcat_s(tmp_path, sizeof(char) * _MAX_PATH, file_info.name);//�����������ļ�·��


				if(strstr(tmp_path, type))//�ж������Ƿ�һ��
				{
					if(remove(tmp_path) == -1)
					{
						show_error(tmp_path);//Ŀ¼�ǿ������ʾ����ԭ��
					}
				}
			}
		}
		_findclose(f_handle);//�رմ򿪵��ļ���������ͷŹ�����Դ�������޷�ɾ����Ŀ¼
	}
	else
	{
		show_error(path);//Ŀ¼�ǿ������ʾ����ԭ��
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
