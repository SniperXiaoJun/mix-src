//
//  functioninterface.c
//  O_All
//
//  Created by YXCD on 13-9-11.
//  Copyright (c) 2013年 YXCD. All rights reserved.
//
#include "func_defb.h"
#include "FILE_LOG.h"

int LOG_TEST()
{
	FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__, "BBB");
}
