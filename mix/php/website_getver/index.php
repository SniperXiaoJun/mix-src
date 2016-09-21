<?php 
include './conn.php';  //数据库链接文件
$sql_notice = mysql_query('SELECT * FROM test where idtest = "1" limit 0,10');
$notice = mysql_fetch_array($sql_notice, MYSQL_ASSOC);
print_r ($notice);
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<title>第一php网提供的教程--将数据库读取的数据生成json格式</title>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<!-- <script src="http://ajax.googleapis.com/ajax/libs/jquery/1.4/jquery.min.js" type="text/javascript"/></script> -->
<script language=javascript>
</script>
</head>
<body>
<pre>
<h1>请注意两种方法生成的对象数组在结构上的区别</h1>
<?php
echo '<h1>法一</h1>';
//假设以下数组是根据我们从数据库读取的数据生成的
$jarr=array('total'=>239,'row'=>array(
           array('code'=>'001','name'=>'中国','addr'=>'Address 11','col4'=>'col4 data'),
           array('code'=>'002','name'=>'Name 2','addr'=>'Address 12','col4'=>'col4 data'),
                                     )
           );
//法一：
$jobj=new stdclass();//实例化stdclass，这是php内置的空类，可以用来传递数据，由于json_decode后的数据是以对象数组的形式存放的，
//所以我们生成的时候也要把数据存储在对象中
foreach($jarr as $key=>$value){
$jobj->$key=$value;
}
print_r($jobj);//打印传递属性后的对象
echo '使用$jobj->row[0][\'code\']输出数组元素:'.$jobj->row[0]['code'].'<br>';
echo '编码后的json字符串：'.json_encode($jobj).'<br>';//打印编码后的json字符串


echo '<hr>';
//法二：
echo '<h1>法二</h1>';
echo '编码后的json字符串：';
echo $str=json_encode($jarr);//将数组进行json编码
echo '<br>';
$arr=json_decode($str);//再进行json解码
print_r($arr);//打印解码后的数组，数据存储在对象数组中
echo '使用$arr->row[0]->code输出数组元素:'.$arr->row[0]->code;

?> 

</body>
</html>