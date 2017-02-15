
#include <stdio.h>

int my_find_middle(int * aArray, int arrayCount)
{
	int middle = 0;
	int left = 0;
	int right = arrayCount -1;

	while(left != right)
	{
		while(right != middle && aArray[right] >= aArray[middle])
		{
			right--;
		}
		if(left != right)
		{
			 aArray[right] = aArray[middle]^ aArray[right];
			 aArray[middle] = aArray[middle]^ aArray[right];
			 aArray[right] = aArray[middle]^ aArray[right];
		}
		middle = right;
		while(left != middle && aArray[left] <= aArray[middle])
		{
			left++;
		}
		if(left != right)
		{
			 aArray[left] = aArray[middle]^ aArray[left];
			 aArray[middle] = aArray[middle]^ aArray[left];
			 aArray[left] = aArray[middle]^ aArray[left];
		}
		middle = left;
	}

	return middle;
}

void my_quick_sort(int * aArray, int aArrayCount)
{
	int middle = 0;

	if(aArrayCount < 2)
	{
		return;
	}

	middle = my_find_middle(aArray, aArrayCount);

	my_quick_sort(aArray, middle);
	my_quick_sort(aArray+middle+1, aArrayCount-1-middle);
}

int main(int argc, char * argv[])
{
	int tmparray[20] = {1,2,3,4,2,2,3,4,4,2,3,4,3,2,3,4,0};

	my_quick_sort(tmparray, 20);

	return 0;
}