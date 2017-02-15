
#ifndef _REGOPERATIONDEFINE_H
#define _REGOPERATIONDEFINE_H

typedef unsigned long DWORD;

#define REG_ROOT_KEY HKEY_LOCAL_MACHINE
#define REG_SUB_KEY "SOFTWARE\\Microsoft\\Windows\\MyKey"

#define REG_VALUE_NAME_HASH "HASH"
#define REG_VALUE_NAME_Symmetric "Symmetric"
#define REG_VALUE_NAME_ASymmetric "ASymmetric"
#define REG_VALUE_NAME_PrivateKey "PrivateKey"
#define REG_VALUE_NAME_RootCert "RootCert"
#define REG_VALUE_NAME_SelfCert "SelfCert"

#define REG_VALUE_DATA_HASH 0
#define REG_VALUE_DATA_Symmetric 0
#define REG_VALUE_DATA_ASymmetric 0
#define REG_VALUE_DATA_PrivateKey ""
#define REG_VALUE_DATA_RootCert ""
#define REG_VALUE_DATA_SelfCert ""

#endif