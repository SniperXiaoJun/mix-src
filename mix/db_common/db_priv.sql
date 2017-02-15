# usr_name = root
# usr_password = root
# db_name = mysql
# procedure = proc_query

use mysql;

grant all privileges on *.* to root@"%" identified by 'root' WITH GRANT OPTION;
grant all privileges on *.* to root@"localhost" identified by 'root' WITH GRANT OPTION;
grant all privileges on *.* to root@"127.0.0.1" identified by 'root' WITH GRANT OPTION;
grant all privileges on procedure mysql.proc_query to root@"%";
grant all privileges on procedure mysql.proc_union_query to root@"%";

FLUSH PRIVILEGES;