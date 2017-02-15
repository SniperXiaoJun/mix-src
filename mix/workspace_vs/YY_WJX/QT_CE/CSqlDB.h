#ifndef CSQLDB_H
#define CSQLDB_H

#include <QString>
#include <QList>

/*�̲���Ϣ�ڿ�*/
typedef struct _SMessage//:: ����        ����         
{
    int mid; //:: ��ʶ         ��ʶ
    QString type; //:: ��������     ��          txt;jpg..;smil;subject;
    QString name; //:: ��������     ��
    QString content; //:: ��������     ��������
} SMessage;

/*�̲���Ϣ*/
typedef struct _SBox
{
    int id; //:: ��ʶ������
    QString sender; //:: �����˺���
    QString date_time; //:: ����/����ʱ��
    QString sign; //:: �Ѷ� y/Y  δ�� n/N
    QString type; //:: ���� 1    ���� 0
    QString location; //:: �����䣬�ռ��䣬�ѷ����䣬�ݸ��䣬�����ļ���
    QString contact; //::����������
} SBox;

/*��ϵ��*/
typedef struct _SContact
{
    int id; //:: ��ʶ������
    QString tel; //:: �绰����
    QString name; //:: ����
    QString cell; //:: �ֻ�����
    QString note; //:: ��ע
    QString group_location; //:: ������        null �����κ���
    QString encrypt; //:: ����    y     ����   n
} SContact;

/*��ϵ����*/
typedef struct _SGroup
{
    int mid;
    QString type; //:: y �ܣ� n ����
    QString name;
} SGroup;

/*�����ļ���*/
typedef struct _SEBold
{
    int id; //:: ��ʶ������               >1
    int fid; //:: ��һ��Ŀ¼             0|1 ��Ŀ¼
    /*start_id �� next_id �ֱ������ļ�����ʼ���ݵ�ID �� ��һ�����ݵ�ID*/
    int start_id; //::��ʼid     
    int next_id; //:: ��һ��id    0|1 ��β     >0��һ��id
    QString name; //:: �ļ�����
    QString type; //:: �ļ�����         txt, �ļ���
    QString title; //:: ����
    QString content; //:: ����
    QString date_time; //:: ����ʱ��
} SEBold;

/*�ʻ��ʺ���Ϣ*/
typedef struct _SAccount
{
    int id; //:: ��ʶ������
    QString id_number; //:: ���֤��
    QString name; //:: ����
    QString acc_number; //:: �����ʺ� 
    QString note; //:: ��ע
} SAccount;

class CSqlDB
{
public:
    CSqlDB();
    ~CSqlDB();

    /*���ӡ��Ͽ��������ݿ�*/
    static void ConnectToDB();
    static void DisConnectToDB();

    /*�����ȡ�����*/
    static bool Box_UpdateSign(int id);
    /*���������е���ϵ����Ϣ*/
    static bool Box_UpdateContact(QString sender = QString(), QString nameto = QString());
    /*ѡ�����ݿ��б��е����ID��+1*/
    static int Box_Select_Max_ID();
    static int Contact_Select_Max_ID();
    static int Group_Select_Max_ID();
    static int EBold_Select_Max_ID();
    static int Account_Select_Max_ID();

    /*��������Ӧ�ṹ��SMessage,SBox,SContact,SGroup,SEBold,SAccount*/
    static bool CreateTable_Message();
    static bool CreateTable_Box();
    static bool CreateTable_Contact();
    static bool CreateTable_Group();
    static bool CreateTable_EBold();
    static bool CreateTable_Account();

    /*��ɾ�Ĳ�Ӧ�ṹ��SMessage*/
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

    /*��ɾ�Ĳ�Ӧ�ṹ��SBox*/
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

    /*��ɾ�Ĳ�Ӧ�ṹ��SContact*/
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

    /*��ɾ�Ĳ�Ӧ�ṹ��SGroup*/
    static bool Group_AddItem(int id = 0, QString type = QString(), QString name = QString());
    static bool Group_DelItem(int id = 0, QString type = QString(), QString name = QString());
    static bool Group_UpdateItem(int * id = NULL, QString * type = NULL, QString * name = NULL);

    static QList<SGroup> Group_SelectItems(int id = 0, QString type = QString(), QString name =
        QString());

    static bool Group_AddItem(SGroup msg);
    static bool Group_DelItem(SGroup msg);
    static bool Group_UpdateItem(SGroup from, SGroup to);

    static QList<SGroup> Group_SelectItems(SGroup msg);

    /*��ɾ�Ĳ�Ӧ�ṹ��SEBold*/
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

    /*��ɾ�Ĳ�Ӧ�ṹ��SAccount*/
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

    /*�Ƴ�����Ӧ�ṹ��SMessage,SBox,SContact,SGroup,SEBold,SAccount*/
    static bool DropTable_Message();
    static bool DropTable_Box();
    static bool DropTable_Contact();
    static bool DropTable_Group();
    static bool DropTable_EBold();
    static bool DropTable_Account();
};

#endif // CSQLDB_H
