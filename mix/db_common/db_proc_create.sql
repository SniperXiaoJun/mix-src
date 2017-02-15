
# tb_name = mysql

use mysql;

#####################################
#proc_union_query
drop PROCEDURE if exists proc_union_query;

delimiter //
CREATE PROCEDURE proc_union_query(IN $fieldList TEXT,
IN $tableList1 TEXT, 
IN $tableList2 TEXT, 
IN $whereList1 TEXT,
IN $whereList2 TEXT,
IN $orderList TEXT, 
IN $pageSize INT,
IN $pageIndex BIGINT,
IN $totalCount BIGINT)
BEGIN

IF !(($fieldList is null OR $fieldList='') OR ($tableList1 is null OR $tableList1='') OR ($tableList2 is null OR $tableList2='')) THEN  
IF ($whereList1 is null OR $whereList1='') THEN  
  SET @new_where1 = ' '; 
ELSE  
  SET @new_where1 = concat(' WHERE ',$whereList1); 
END IF; 

IF ($whereList2 is null OR $whereList2='') THEN  
  SET @new_where2 = ' '; 
ELSE  
  SET @new_where2 = concat(' WHERE ',$whereList2); 
END IF; 

IF ($orderList is null OR $orderList='') THEN 
  SET @new_order = ' '; 
ELSE  
  SET @new_order =concat(' ORDER BY ',$orderList);  
END IF; 

SET @limitStart = $pageSize * $pageIndex;

SET @SqlQuery = concat(' SELECT ',$fieldList,' FROM ',$tableList1, @new_where1, ' union ',' SELECT ',$fieldList,' FROM ',$tableList2, @new_where2, @new_order,' limit ', @limitStart, ',', $PageSize);  

Prepare stmtQuery from @SqlQuery;
execute stmtQuery;

IF $totalCount = 0 THEN
	#符合条件的记录总数
	SET @SqlCount = concat(' SELECT COUNT(*) as 总数 from ', '( select ',$fieldList ,' from ', $tableList1,@new_where1,' union ', ' select ' ,$fieldList,' FROM ',$tableList2,@new_where2, ') TableTemp');
    PREPARE stmtCount FROM @SqlCount;
    EXECUTE stmtCount;
END IF;

END IF;

END//
delimiter ;
					 
		

#####################################
# proc_query

drop PROCEDURE if exists proc_query;

delimiter //
CREATE PROCEDURE proc_query(IN $fieldList TEXT,
IN $tableList TEXT, 
IN $whereList TEXT,
IN $orderList TEXT, 
IN $pageSize INT,
IN $pageIndex BIGINT,
IN $totalCount BIGINT)
BEGIN

IF !(($fieldList is null OR $fieldList='') OR ($tableList is null OR $tableList='')) THEN  
IF ($whereList is null OR $whereList='') THEN  
  SET @new_where = ' '; 
ELSE  
  SET @new_where = concat(' WHERE ',$whereList); 
END IF; 

IF ($orderList is null OR $orderList='') THEN 
  SET @new_order = ' '; 
ELSE  
  SET @new_order =concat(' ORDER BY ',$orderList);  
END IF; 

SET @limitStart = $pageSize * $pageIndex;

SET @SqlQuery = concat('SELECT ',$fieldList,' FROM ',$tableList, @new_where, @new_order,' limit ', @limitStart, ',', $PageSize);  

Prepare stmtQuery from @SqlQuery;
execute stmtQuery;

IF $totalCount = 0 THEN
	#符合条件的记录总数
	SET @SqlCount = concat('SELECT COUNT(*) as 总数 FROM ',$tableList,@new_where);
    PREPARE stmtCount FROM @SqlCount;
    EXECUTE stmtCount;
END IF;

END IF;

END//
delimiter ;