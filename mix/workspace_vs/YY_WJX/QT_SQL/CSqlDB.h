#ifndef CSQLDB_H
#define CSQLDB_H

#include <QString>
#include <QList>

/*短彩信息内空*/
typedef struct _SMessage//:: 彩信        短信         
{
    int mid; //:: 标识         标识
    QString type; //:: 附件类型     无          txt;jpg..;smil;subject;
    QString name; //:: 附件名字     无
    QString content; //:: 附件内容     短信内容
} SMessage;

/*短彩信息*/
typedef struct _SBox
{
    int id; //:: 标识，主键
    QString sender; //:: 发件人号码
    QString date_time; //:: 接收/发送时间
    QString sign; //:: 已读 y/Y  未读 n/N
    QString type; //:: 短信 1    彩信 0
    QString location; //:: 发件箱，收件箱，已发信箱，草稿箱，加密文件夹
    QString contact; //::发件人姓名
} SBox;

/*联系人*/
typedef struct _SContact
{
    int id; //:: 标识，主键
    QString tel; //:: 电话号码
    QString name; //:: 姓名
    QString cell; //:: 手机号码
    QString note; //:: 备注
    QString group_location; //:: 所在组        null 不在任何组
    QString encrypt; //:: 加密    y     非密   n
} SContact;

/*联系人组*/
typedef struct _SGroup
{
    int mid;
    QString type; //:: y 密， n 非密
    QString name;
} SGroup;

/*加密文件夹*/
typedef struct _SEBold
{
    int id; //:: 标识，主键               >1
    int fid; //:: 上一级目录             0|1 根目录
    /*start_id 和 next_id 分别代表大文件的起始内容的ID 和 下一段内容的ID*/
    int start_id; //::起始id     
    int next_id; //:: 下一段id    0|1 结尾     >0下一个id
    QString name; //:: 文件名称
    QString type; //:: 文件类型         txt, 文件夹
    QString title; //:: 标题
    QString content; //:: 内容
    QString date_time; //:: 创建时间
} SEBold;

/*帐户帐号信息*/
typedef struct _SAccount
{
    int id; //:: 标识，主键
    QString id_number; //:: 身份证号
    QString name; //:: 姓名
    QString acc_number; //:: 银行帐号 
    QString note; //:: 备注
} SAccount;

class CSqlDB
{
public:
    CSqlDB();
    ~CSqlDB();

    /*连接、断开连接数据库*/
    static void ConnectToDB();
    static void DisConnectToDB();

    /*标记与取消标记*/
    static bool Box_UpdateSign(int id);
    /*更新信箱中的联系人信息*/
    static bool Box_UpdateContact(QString sender = QString(), QString nameto = QString());
    /*选择数据库中表中的最大ID号+1*/
    static int Box_Select_Max_ID();
    static int Contact_Select_Max_ID();
    static int Group_Select_Max_ID();
    static int EBold_Select_Max_ID();
    static int Account_Select_Max_ID();

    /*创建表格对应结构体SMessage,SBox,SContact,SGroup,SEBold,SAccount*/
    static bool CreateTable_Message();
    static bool CreateTable_Box();
    static bool CreateTable_Contact();
    static bool CreateTable_Group();
    static bool CreateTable_EBold();
    static bool CreateTable_Account();

    /*增删改查应结构体SMessage*/
    static bool Message_AddItem(int id = 0, QString type = QString(), QString name = QString(),
        QString content = QString());
    static bool Message_DelItem(int id = 0, QString type = QString(), QString name = QString(),
        QString content = QString());
    static bool Message_UpdateItem(int * id = NULL, QString * type = NULL, QString * name = NULL,
        QString * content = NULL);

    static QList<SMessage> Message_SelectItems(int id = 0, QString type = QString(), QString name =
        QString(), QString content = QString());

    static bool Message_AddItem(SMessage msg);
    static bool Message_DelItem(SMessage msg);
    static bool Message_UpdateItem(SMessage from, SMessage to);

    static QList<SMessage> Message_SelectItems(SMessage msg);

    /*增删改查应结构体SBox*/
    static bool Box_AddItem(int id = 0, QString sender = QString(), QString date_time = QString(),
        QString sign = QString(), QString type = QString(), QString location = QString(),
        QString contact = QString());
    static bool Box_DelItem(int id = 0, QString sender = QString(), QString date_time = QString(),
        QString sign = QString(), QString type = QString(), QString location = QString(),
        QString contact = QString());
    static bool Box_UpdateItem(int * id = NULL, QString * sender = NULL,
        QString * date_time = NULL, QString * sign = NULL, QString * type = NULL,
        QString * location = NULL, QString * contact = NULL);

    static QList<SBox>
    Box_SelectItems(int id = 0, QString sender = QString(), QString date_time = QString(),
        QString sign = QString(), QString type = QString(), QString location = QString(),
        QString contact = QString());

    static bool Box_AddItem(SBox box);
    static bool Box_DelItem(SBox box);
    static bool Box_UpdateItem(SBox from, SBox to);

    static QList<SBox> Box_SelectItems(SBox box);

    /*增删改查应结构体SContact*/
    static bool Contact_AddItem(int id = 0, QString tel = QString(), QString name = QString(),
        QString cell = QString(), QString note = QString(), QString group = QString(),
        QString encrypt = QString());
    static bool Contact_DelItem(int id = 0, QString tel = QString(), QString name = QString(),
        QString cell = QString(), QString note = QString(), QString group = QString(),
        QString encrypt = QString());
    static bool Contact_UpdateItem(int * id = NULL, QString * tel = NULL, QString * name = NULL,
        QString * cell = NULL, QString * note = NULL, QString * group = NULL, QString * encrypt =
            NULL);

    static QList<SContact> Contact_SelectItems(int id = 0, QString tel = QString(), QString name =
        QString(), QString cell = QString(), QString note = QString(), QString group = QString(),
        QString encrypt = QString());

    static bool Contact_AddItem(SContact contact);
    static bool Contact_DelItem(SContact contact);
    static bool Contact_UpdateItem(SContact from, SContact to);

    static QList<SContact> Contact_SelectItems(SContact contact);

    /*增删改查应结构体SGroup*/
    static bool Group_AddItem(int id = 0, QString type = QString(), QString name = QString());
    static bool Group_DelItem(int id = 0, QString type = QString(), QString name = QString());
    static bool Group_UpdateItem(int * id = NULL, QString * type = NULL, QString * name = NULL);

    static QList<SGroup> Group_SelectItems(int id = 0, QString type = QString(), QString name =
        QString());

    static bool Group_AddItem(SGroup msg);
    static bool Group_DelItem(SGroup msg);
    static bool Group_UpdateItem(SGroup from, SGroup to);

    static QList<SGroup> Group_SelectItems(SGroup msg);

    /*增删改查应结构体SEBold*/
    static bool EBold_AddItem(int id = 0, int fid = 0, int start_id = 0, int next_id = 0,
        QString name = QString(), QString type = QString(), QString title = QString(),
        QString content = QString(), QString date_time = QString());

    static bool EBold_DelItem(int id = 0);

    static bool EBold_UpdateItem(int * id = NULL, int * fid = NULL, int * start_id = NULL,
        int * next_id = NULL, QString * name = NULL, QString *type = NULL, QString * title = NULL,
        QString * content = NULL, QString * date_time = NULL);

    static QList<SEBold> EBold_SelectItems(int id = 0, int fid = 0, int start_id = 0, int next_id =
        0, QString name = QString(), QString type = QString(), QString title = QString(),
        QString content = QString(), QString date_time = QString());

    static bool EBold_AddItem(SEBold msg);
    static bool EBold_DelItem(SEBold msg);
    static bool EBold_UpdateItem(SEBold from, SEBold to);

    static QList<SEBold> EBold_SelectItems(SEBold msg);

    /*增删改查应结构体SAccount*/
    static bool Account_AddItem(int id = 0, QString id_number = QString(),
        QString name = QString(), QString acc_number = QString(), QString note = QString());
    static bool Account_DelItem(int id = 0, QString id_number = QString(),
        QString name = QString(), QString acc_number = QString(), QString note = QString());
    static bool Account_UpdateItem(int * id = NULL, QString * id_number = NULL, QString * name =
        NULL, QString * acc_number = NULL, QString * note = NULL);

    static QList<SAccount> Account_SelectItems(int id = 0, QString id_number = QString(),
        QString name = QString(), QString acc_number = QString(), QString note = QString());

    static bool Account_AddItem(SAccount msg);
    static bool Account_DelItem(SAccount msg);
    static bool Account_UpdateItem(SAccount from, SAccount to);

    static QList<SAccount> Account_SelectItems(SAccount msg);

    /*移除表格对应结构体SMessage,SBox,SContact,SGroup,SEBold,SAccount*/
    static bool DropTable_Message();
    static bool DropTable_Box();
    static bool DropTable_Contact();
    static bool DropTable_Group();
    static bool DropTable_EBold();
    static bool DropTable_Account();
};

#endif // CSQLDB_H
