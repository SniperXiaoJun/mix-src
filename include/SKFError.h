#ifndef __SKFERROR_H
#define __SKFERROR_H

#define	SAR_OK							0x00000000		//�ɹ�
#define	SAR_FAIL						0x0A000001		//ʧ��
#define	SAR_UNKNOWNERR					0x0A000002		//�쳣����
#define	SAR_NOTSUPPORTYETERR			0x0A000003		//��֧�ֵķ���
#define	SAR_FILEERR						0x0A000004		//�ļ���������
#define	SAR_INVALIDHANDLEERR			0x0A000005		//��Ч�ľ��
#define	SAR_INVALIDPARAMERR				0x0A000006		//��Ч�Ĳ���
#define	SAR_READFILEERR					0x0A000007		//���ļ�����
#define	SAR_WRITEFILEERR				0x0A000008		//д�ļ�����
#define	SAR_NAMELENERR					0x0A000009		//���Ƴ��ȴ���
#define	SAR_KEYUSAGEERR					0x0A00000A		//��Կ��;����
#define	SAR_MODULUSLENERR				0x0A00000B		//ģ�ĳ��ȴ���
#define	SAR_NOTINITIALIZEERR			0x0A00000C		//δ��ʼ��
#define	SAR_OBJERR						0x0A00000D		//�������
#define	SAR_MEMORYERR					0x0A00000E		//�ڴ����
#define	SAR_TIMEOUTERR					0x0A00000F		//��ʱ
#define	SAR_INDATALENERR				0x0A000010		//�������ݳ��ȴ���
#define	SAR_INDATAERR					0x0A000011		//�������ݴ���
#define	SAR_GENRANDERR					0x0A000012		//�������������
#define	SAR_HASHOBJERR					0x0A000013		//HASH�����
#define	SAR_HASHERR						0x0A000014		//HASH�������
#define	SAR_GENRSAKEYERR				0x0A000015		//����RSA��Կ��
#define	SAR_RSAMODULUSLENERR			0x0A000016		//RSA��Կģ������
#define	SAR_CSPIMPRTPUBKEYERR			0x0A000017		//CSP�����빫Կ����
#define	SAR_RSAENCERR					0x0A000018		//RSA���ܴ���
#define	SAR_RSADECERR					0x0A000019		//RSA���ܴ���
#define	SAR_HASHNOTEQUALERR				0x0A00001A		//HASHֵ�����
#define	SAR_KEYNOTFOUNTERR				0x0A00001B		//��Կδ����
#define	SAR_CERTNOTFOUNTERR				0x0A00001C		//֤��δ����
#define	SAR_NOTEXPORTERR				0x0A00001D		//����δ����
#define	SAR_DECRYPTPADERR				0x0A00001E		//����ʱ����������
#define	SAR_MACLENERR					0x0A00001F		//MAC���ȴ���
#define	SAR_BUFFER_TOO_SMALL			0x0A000020		//����������
#define	SAR_KEYINFOTYPEERR				0x0A000021		//��Կ���ʹ���
#define	SAR_NOT_EVENTERR				0x0A000022		//���¼�����
#define	SAR_DEVICE_REMOVED				0x0A000023		//�豸���Ƴ�
#define	SAR_PIN_INCORRECT				0x0A000024		//PIN����ȷ
#define	SAR_PIN_LOCKED					0x0A000025		//PIN������
#define	SAR_PIN_INVALID					0x0A000026		//PIN��Ч
#define	SAR_PIN_LEN_RANGE				0x0A000027		//PIN���ȴ���
#define	SAR_USER_ALREADY_LOGGED_IN		0x0A000028		//�û��Ѿ���¼
#define	SAR_USER_PIN_NOT_INITIALIZED	0x0A000029		//û�г�ʼ���û�����
#define	SAR_USER_TYPE_INVALID			0x0A00002A		//PIN���ʹ���
#define	SAR_APPLICATION_NAME_INVALID	0x0A00002B		//Ӧ��������Ч
#define	SAR_APPLICATION_EXISTS			0x0A00002C		//Ӧ���Ѿ�����
#define	SAR_USER_NOT_LOGGED_IN			0x0A00002D		//�û�û�е�¼
#define	SAR_APPLICATION_NOT_EXISTS		0x0A00002E		//Ӧ�ò�����
#define	SAR_FILE_ALREADY_EXIST			0x0A00002F		//�ļ��Ѿ�����
#define	SAR_NO_ROOM						0x0A000030		//�ռ䲻��
#define	SAR_FILE_NOT_EXIST				0x0A000031		//�ļ�������
#define	SAR_REACH_MAX_CONTAINER_COUNT	0x0A000032		//�Ѵﵽ���ɹ���������

#endif //__SKFERROR_H

