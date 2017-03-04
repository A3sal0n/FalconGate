<?php
session_start();

include_once 'includes/functions.php';

?>

<?php
if (login_check() != true){
    echo ("<p><span class=error_message>You are not authorized to access this page. Please </span><a href=index.php>login</a>.</p>");
    exit(0);
}
require 'templates/header.html';
?>
<?php  $lines =(!isset($_GET['lines'])) ? '50': $_GET['lines']; ?>
<h1>System Overview</h1>
<h3>The last <?php echo $lines ?> lines of /var/log/syslog</h3>
<p>How many lines to display? <form action="" method="get">
	<select name="lines" onchange="this.form.submit()">
		<option value="50" <?php echo ($lines=='50') ? 'selected':'' ?>>50</option>
		<option value="100" <?php echo ($lines=='100') ? 'selected':'' ?>>100</option>
		<option value="500" <?php echo ($lines=='500') ? 'selected':'' ?>>500</option>
</select>
</form></p>
<textarea cols="160" rows="50" wrap="off" readonly="readonly" id="textarea" style="width:99%; font-family:'Courier New', Courier, mono; font-size:11px;background:#E5E5E5;color:#000000;">
<?php

$lines2=array();
$fp = fopen("/var/log/syslog", "rb");
while(!feof($fp))
{
 $line = fgets($fp, 4096);
 if (strpos($line, "FG-") == true)
	array_push($lines2, $line);
 elseif (strpos($line, "FG-DEBUG") == true) {
 }
 else {
 }
// if (strpos($line, "FG-DEBUG") == true){
// }
// else
//	array_push($lines2, $line); 
 if (count($lines2)>500)
   array_shift($lines2);
}
fclose($fp);

$output = array_reverse($lines2);
while ($a <= $lines) {
$a++;
echo $output[$a];
}
?>
</textarea>

<?php
require 'templates/footer.html';
?>
