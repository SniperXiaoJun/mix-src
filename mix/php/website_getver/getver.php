<?php 
$con = mysql_connect("localhost", "root", "root");

if (!$con)
{
  die('Could not connect: ' . mysql_error());
}

$db_selected = mysql_select_db("test",$con);
$sql = 'SELECT * FROM test';
$result = mysql_query($sql,$con);
while($row = mysql_fetch_array($result,MYSQL_ASSOC))
{
	echo $str=json_encode($row);//将数组进行json编码
}
mysql_free_result($result);
mysql_close($con);
?>