CREATE DATABASE  IF NOT EXISTS `db_ebt_kms` /*!40100 DEFAULT CHARACTER SET utf8 */;
USE `db_ebt_kms`;
-- MySQL dump 10.13  Distrib 5.6.13, for Win32 (x86)
--
-- Host: localhost    Database: db_ebt_kms
-- ------------------------------------------------------
-- Server version	5.6.14

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `audit`
--

DROP TABLE IF EXISTS `audit`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `audit` (
  `_ID` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '自增ID',
  `_NAME` varchar(60) DEFAULT NULL COMMENT '姓名',
  `_SN` varchar(255) DEFAULT NULL COMMENT '序列号',
  `_TYPE` tinyint(3) unsigned DEFAULT '0' COMMENT '日志类型',
  `_EVENT` varchar(255) DEFAULT NULL COMMENT '日志时间',
  `_STATUS` int(11) DEFAULT '0' COMMENT '日志状态',
  `_IP` varchar(255) DEFAULT NULL COMMENT 'IP地址',
  `_DESC` varchar(255) DEFAULT NULL COMMENT '日志描述',
  `_MONEY` varchar(255) DEFAULT NULL COMMENT '金额',
  `_FROMCARD` varchar(255) DEFAULT NULL COMMENT '付款卡号',
  `_TOCARD` varchar(255) DEFAULT NULL COMMENT '收款卡号',
  `_DATETIME` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '时间',
  PRIMARY KEY (`_ID`),
  KEY `_DATETIME` (`_DATETIME`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COMMENT='日志审计表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `certcrl`
--

DROP TABLE IF EXISTS `certcrl`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `certcrl` (
  `_ID` bigint(20) NOT NULL AUTO_INCREMENT COMMENT '自增ID',
  `_VALUE` blob COMMENT '吊销列表内容',
  `_DATETIME` timestamp NULL DEFAULT CURRENT_TIMESTAMP COMMENT '生成日期',
  PRIMARY KEY (`_ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COMMENT='证书吊销列表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `user`
--

DROP TABLE IF EXISTS `user`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `user` (
  `_ID` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '自增ID',
  `_NAME` varchar(60) DEFAULT NULL COMMENT '姓名',
  `_NICKNAME` varchar(60) DEFAULT NULL COMMENT '昵称',
  `_PASSWORD` varchar(255) DEFAULT NULL COMMENT '登陆密码',
  `_ACCOUNT_NO` varchar(32) DEFAULT NULL COMMENT '账户号码',
  `_CERT_TYPE` varchar(1) DEFAULT NULL COMMENT '证件类型',
  `_CERT_NO` varchar(20) DEFAULT NULL COMMENT '证件号码',
  `_SEC_MSG` varchar(255) DEFAULT NULL COMMENT '安全信息',
  `_SEX` varchar(1) DEFAULT NULL COMMENT '性别',
  `_ADDRESS` varchar(255) DEFAULT NULL COMMENT '地址',
  `_ZIP_CODE` varchar(6) DEFAULT NULL COMMENT '邮编',
  `_TELEPHONE` varchar(12) DEFAULT NULL COMMENT '电话',
  `_MOBILE` varchar(15) DEFAULT NULL COMMENT '手机',
  `_EMAIL` varchar(60) DEFAULT NULL COMMENT '邮箱',
  `_CREATE` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `_UPDATE` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00' COMMENT '更改时间',
  `_IP` varchar(60) DEFAULT NULL COMMENT '最后一次登录IP',
  `_HASH` varchar(255) DEFAULT NULL COMMENT '登录凭证',
  `_DATETIME` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00' COMMENT '登录日期',
  `_COUNT` bigint(20) DEFAULT '0' COMMENT '登录次数',
  `_ERR_COUNT` bigint(20) DEFAULT '0' COMMENT '错误登录次数',
  `_ERR_TIME` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00' COMMENT '错误登录时间',
  `_PUBLIC_KEY` tinyblob COMMENT '用户公钥',
  PRIMARY KEY (`_ID`),
  UNIQUE KEY `_NICKNAME` (`_NICKNAME`),
  UNIQUE KEY `_ACCOUNT_NO` (`_ACCOUNT_NO`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COMMENT='用户表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `usercert`
--

DROP TABLE IF EXISTS `usercert`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `usercert` (
  `_ID` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '自增ID',
  `_UID` bigint(20) unsigned DEFAULT NULL COMMENT '用户信息ID',
  `_TYPE` tinyint(3) DEFAULT NULL COMMENT '类型0：根证书；1：签名证书；2：加密证书',
  `_KEY_VALUE` blob COMMENT '密钥',
  `_REQ_VALUE` blob COMMENT '证书请求',
  `_CERT_VALUE` blob COMMENT '证书内容',
  `_CERT_SN` bigint(20) unsigned DEFAULT NULL COMMENT '证书序列号',
  `_CERT_TIME` bigint(20) unsigned DEFAULT NULL COMMENT '有效期',
  `_CERT_TIME_CREATE` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00' COMMENT '证书创建时间',
  `_CERT_TIME_UPDATE` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00' COMMENT '证书更新时间',
  `_REASON` tinyint(4) DEFAULT '0' COMMENT '吊销缘由',
  `_STATE` int(11) DEFAULT '0' COMMENT '吊销状态',
  `_DATETIME` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00' COMMENT '吊销日期',
  PRIMARY KEY (`_ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COMMENT='用户证书表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `userinfo`
--

DROP TABLE IF EXISTS `userinfo`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `userinfo` (
  `_ID` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '自增ID',
  `_TYPE` tinyint(3) DEFAULT NULL COMMENT '类型0：根证书；1：用户证书',
  `_countryName` varchar(60) DEFAULT NULL COMMENT '国家',
  `_stateOrProvinceName` varchar(60) DEFAULT NULL COMMENT '省份（州）',
  `_localityName` varchar(60) DEFAULT NULL COMMENT '城市',
  `_organizationName` varchar(60) DEFAULT NULL COMMENT '组织',
  `_organizationalUnitName` varchar(60) DEFAULT NULL COMMENT '单位',
  `_commonName` varchar(60) DEFAULT NULL COMMENT '通用名',
  `_challengePassword` varchar(60) DEFAULT NULL COMMENT '挑战码',
  `_unstructuredName` varchar(60) DEFAULT NULL COMMENT 'unstructuredName',
  `_idCardNumber` varchar(60) DEFAULT NULL COMMENT '身份证号',
  `_emailAddress` varchar(60) DEFAULT NULL COMMENT '邮件地址',
  `_DATETIME` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',
  `_certstate` tinyint(3) NOT NULL DEFAULT '0' COMMENT '证书状态：0 不存在；1 存在',
  PRIMARY KEY (`_ID`),
  UNIQUE KEY `_commonName_UNIQUE` (`_commonName`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COMMENT='用户信息表';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping routines for database 'db_ebt_kms'
--
/*!50003 DROP PROCEDURE IF EXISTS `proc_query` */;
/*!50003 SET @saved_cs_client      = @@character_set_client */ ;
/*!50003 SET @saved_cs_results     = @@character_set_results */ ;
/*!50003 SET @saved_col_connection = @@collation_connection */ ;
/*!50003 SET character_set_client  = utf8 */ ;
/*!50003 SET character_set_results = utf8 */ ;
/*!50003 SET collation_connection  = utf8_general_ci */ ;
/*!50003 SET @saved_sql_mode       = @@sql_mode */ ;
/*!50003 SET sql_mode              = 'STRICT_TRANS_TABLES,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION' */ ;
DELIMITER ;;
CREATE DEFINER=`root`@`localhost` PROCEDURE `proc_query`(IN $fieldList TEXT,
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
	
	SET @SqlCount = concat('SELECT COUNT(*) as total FROM ',$tableList,@new_where);
    PREPARE stmtCount FROM @SqlCount;
    EXECUTE stmtCount;
END IF;

END IF;

END ;;
DELIMITER ;
/*!50003 SET sql_mode              = @saved_sql_mode */ ;
/*!50003 SET character_set_client  = @saved_cs_client */ ;
/*!50003 SET character_set_results = @saved_cs_results */ ;
/*!50003 SET collation_connection  = @saved_col_connection */ ;
/*!50003 DROP PROCEDURE IF EXISTS `proc_union_query` */;
/*!50003 SET @saved_cs_client      = @@character_set_client */ ;
/*!50003 SET @saved_cs_results     = @@character_set_results */ ;
/*!50003 SET @saved_col_connection = @@collation_connection */ ;
/*!50003 SET character_set_client  = utf8 */ ;
/*!50003 SET character_set_results = utf8 */ ;
/*!50003 SET collation_connection  = utf8_general_ci */ ;
/*!50003 SET @saved_sql_mode       = @@sql_mode */ ;
/*!50003 SET sql_mode              = 'STRICT_TRANS_TABLES,NO_AUTO_CREATE_USER,NO_ENGINE_SUBSTITUTION' */ ;
DELIMITER ;;
CREATE DEFINER=`root`@`localhost` PROCEDURE `proc_union_query`(IN $fieldList TEXT,
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
	
	SET @SqlCount = concat(' SELECT COUNT(*) as total from ', '( select ',$fieldList ,' from ', $tableList1,@new_where1,' union ', ' select ' ,$fieldList,' FROM ',$tableList2,@new_where2, ') TableTemp');
    PREPARE stmtCount FROM @SqlCount;
    EXECUTE stmtCount;
END IF;

END IF;

END ;;
DELIMITER ;
/*!50003 SET sql_mode              = @saved_sql_mode */ ;
/*!50003 SET character_set_client  = @saved_cs_client */ ;
/*!50003 SET character_set_results = @saved_cs_results */ ;
/*!50003 SET collation_connection  = @saved_col_connection */ ;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2015-06-05 14:55:03
