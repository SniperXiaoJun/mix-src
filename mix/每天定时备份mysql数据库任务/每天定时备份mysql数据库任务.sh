����
 
1��ÿ��4�㱸��mysql���ݣ�
 
2��Ϊ��ʡ�ռ䣬ɾ������3���µ����б������ݣ�
 
3��ɾ������7��ı������ݣ�����3������� 10�� 20�� 30�ŵı������ݣ�
 
 
 
#����shell�ļ�
vim backup_mysql.sh
 
mysqldump -uroot -p123456 --all-databases > /data/dbdata/mysqlbak/`date +%Y%m%d`.sql
find /data/dbdata/mysqlbak/ -mtime +7 -name '*[1-9].sql' -exec rm -rf {} \;
find /data/dbdata/mysqlbak/ -mtime +92 -name '*.sql' -exec rm -rf {} \;
 
#������ʱ����
crontab �Ce
0 4 * * *  /data/dbdata/backup_mysql.sh