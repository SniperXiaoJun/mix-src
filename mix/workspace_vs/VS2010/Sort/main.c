

#include <stdio.h>
#include <stdlib.h>


//选择排序1
int Selection_Sort(int * pArray, int iCount)
{
	int i = 0;
	int j = 0;

	for(; i < iCount; i++)
	{
		for(j = i+1; j < iCount; j++)
		{
			if(pArray[i] > pArray[j])
			{
				pArray[i] = pArray[i]^pArray[j];
				pArray[j] = pArray[i]^pArray[j];
				pArray[i] = pArray[i]^pArray[j];
			}
		}
	}

	return 0;
}
//选择排序2
int __Selection_Sort(int * pArray, int iCount)
{
	int i = 0;
	int j = 0;

	int temp = 0;

	for(; i < iCount; i++)
	{
		temp = i;
		for(j = i+1; j < iCount; j++)
		{
			if(pArray[temp] > pArray[j])
			{
				//pArray[i] = pArray[i]^pArray[j];
				//pArray[j] = pArray[i]^pArray[j];
				//pArray[i] = pArray[i]^pArray[j];
				temp = j;
			}
		}
		if(temp != i)
		{
			pArray[i] = pArray[i]^pArray[temp];
			pArray[temp] = pArray[i]^pArray[temp];
			pArray[i] = pArray[i]^pArray[temp];
		}
	}

	return 0;
}

//冒泡排序1
int Bubble_Sort(int * pArray, int iCount)
{
	int i = 0;
	int j = 0;

	for(i = 0; i < iCount; i++)
	{
		for(j = 0; j < iCount - i - 1; j++)
		{
			if(pArray[j] > pArray[j+1])
			{
				pArray[j] = pArray[j]^pArray[j+1];
				pArray[j+1] = pArray[j]^pArray[j+1];
				pArray[j] = pArray[j]^pArray[j+1];
			}
		}
	}

	return 0;
}

//冒泡排序2
int __Bubble_Sort(int * pArray, int iCount)
{
	int i = 0;
	int j = 0;

	int temp = 0;

	for(i = 0; i < iCount; i++)
	{
		temp = 0;

		for(j = 0; j < iCount - i - 1; j++)
		{
			if(pArray[temp] > pArray[j+1])
			{
				temp = j+1;
			}
		}
		if(temp != iCount-i -1)
		{
			pArray[temp] = pArray[iCount-i-1]^pArray[temp];
			pArray[iCount-i-1] = pArray[iCount-i-1]^pArray[temp];
			pArray[temp] = pArray[iCount-i-1]^pArray[temp];
		}
	}
	return 0;
}

//快速排序
int __partions(int * pArray,int low,int high)
{
	int center_value = pArray[high];

	for(; low < high;)
	{
		for(; low < high && pArray[low] <= center_value; low++)
		{

		}
		pArray[high] = pArray[low];

		for(; low < high && pArray[high] >= center_value; high--)
		{

		}
		pArray[low] = pArray[high];
	}

	pArray[low] = center_value;

	return low;
}

int __qsort(int *pArray,int low,int high)
{
	if(low < high)
	{
		int center = __partions(pArray, low, high);

		__qsort(pArray, low, center - 1);
		__qsort(pArray, center + 1, high);
	}

	return 0;
}

int __quicksort(int * pArray, int count)
{
	__qsort(pArray, 0, count - 1);//第一个作为枢轴 ，从第0个排到第n-1个

	return 0;
}


//int partions(int l[],int low,int high)
//{
//	int prvotkey = l[low];
//
//	while (low < high)
//	{
//		while (low < high && l[high] >= prvotkey)
//			--high;
//		l[low]=l[high];
//		while (low < high && l[low] <= prvotkey) 
//			++low;
//		l[high]=l[low];
//	}
//
//	l[low] = prvotkey;
//
//	return low;
//}
//
//void qsort(int l[],int low,int high)
//{
//	int prvotloc;
//
//	if(low < high)
//	{
//		prvotloc = partions(l,low,high);    //将第一次排序的结果作为枢轴
//
//		qsort(l, low,prvotloc - 1); //递归调用排序 由low 到prvotloc-1
//		qsort(l, prvotloc + 1,high); //递归调用排序 由 prvotloc+1到 high
//
//	}
//}

//void quicksort(int l[],int n)
//{
//	qsort(l,0,n -1); //第一个作为枢轴 ，从第0个排到第n-1个
//}


//归并排序
int __merge(int parray[],int nleft, int nright)
{
	int * parray_left = malloc(nleft * 4);
	int * parray_right = malloc(nright * 4);

	int i = 0;
	int k = 0;
	int j = 0;

	for(i = 0; i < nleft; i++)
	{
		parray_left[i] = parray[i];
	}

	for(j = 0; j < nright; j++)
	{
		parray_right[j] = parray[nleft + j];
		
	}

	for(i = 0, j = 0, k = 0; k < (nleft + nright); k++)
	{
		if(i == nleft)
		{
			parray[k] = parray_right[j];
			j++;
		}
		else if(j == nright)
		{
			parray[k] = parray_left[i];
			i++;
		}
		else if( parray_left[i] < parray_right[j])
		{
			parray[k] = parray_left[i];
			i++;
		}
		else
		{
			parray[k] = parray_right[j];
			j++;
		}
	}

	//for(i = 0, j = 0, k = 0; i < nleft && j < nright; k++)
	//{
	//	if(parray_left[i] < parray_right[j])
	//	{
	//		parray[k] = parray_left[i];
	//		i++;
	//	}
	//	else
	//	{
	//		parray[k] = parray_right[j];
	//		j++;
	//	}
	//}

	//while(i < nleft)
	//{
	//	parray[k] = parray_left[i];
	//	k++;
	//	i++;
	//}
	//while(j < nright)
	//{
	//	parray[k] = parray_right[j];
	//	k++;
	//	j++;
	//}

	free(parray_left);
	free(parray_right);

	return 0;
}

int __merge_sort(int * a, int n)
{
	int i = 0;
	int j = 0;

	if(n == 0 || n == 1)
	{
		return 0;
	}
	else
	{	
		__merge_sort(a, n/2);
		__merge_sort(a + n/2, n - n/2);

		__merge(a, n/2, n - n/2);


	//	for(i = 0 , j = n/2; i < n/2 && j < n;)
	//	{
	//		while(a[i] < a[j] && i < n/2 && j < n)
	//		{
	//			i ++;
	//		}

	//		if(i != j && i < n/2 && j < n)
	//		{
	//			a[i] = a[i]^a[j];
	//			a[j] = a[i]^a[j];
	//			a[i] = a[i]^a[j];

	//			i++;
	//		}

	//		while(a[j] > a[j+1] && j+1 < n)
	//		{
	//			a[j] = a[j]^a[j+1];
	//			a[j+1] = a[j]^a[j+1];
	//			a[j] =a[j]^a[j+1];;

	//			j++;
	//		}
	//		j = n/2;
	//	}
	}

	return 0;
}

//typedef int (* fun_templete_type)(int x, int y);
//
//int fun_type(fun_templete_type fun_ob, int x, int y)
//{
//	return fun_ob(x, y);
//}

int fun(int (*fun_templete)(int x, int y), int x, int y)
{
	return fun_templete(x, y);
}

int max_xy(int x, int y)
{
	return (x > y? x:y);
}



int main(int argc, char *argv[]) {
	//int a[11] = {1, 3, 5, 7, 9, 2, 4, 6, 8, 10, 0};
	//int i = 0;
	//int n = 11;
	//printf("\nberfroe sort!\n");

	//for(i=0;i<n;i++)
	//{
	//	printf("%3d",a[i]);
	//}

	int j;

	int (*fun_templete)(int x, int y);

	fun_templete = &max_xy;

	 //j = (*fun_templete)(2,5);
	j = fun(max_xy ,2, 5);

	 printf("%d", j);


	//__merge_sort(a,n);

	//printf("\nafter sort!\n");

	//for(i=0;i<n;i++)
	//{
	//	printf("%3d",a[i]);
	//}

	//getchar();

	return 0;
}

