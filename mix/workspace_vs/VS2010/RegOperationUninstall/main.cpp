
 
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#include "../RegOperationInterface/RegOperation.h"
 
int main(int argc, char* argv[])
{  
    return CRegOperation::Uninstall();
}