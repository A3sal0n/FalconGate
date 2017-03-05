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
<?php
$log_count = (!isset($_GET['log_count'])) ? '50': $_GET['log_count'];
$data = array("target" => "logs", "log_count" => $log_count);
$result = CallAPI('POST', 'http://127.0.0.1:5000/api/v1.0/falcongate/status', json_encode($data));
if (!$result){
    echo ("<h3><span class=error_message>FalconGate API process seems to be down!</span></h3>");
    echo ("<h3><span class=error_message>Check your device's configuration and reboot if necessary.</span></h3>");
}else{
	$obj = json_decode($result, true);
?>
<h1>System Overview</h1>
<h3>The last <?php echo $log_count ?> lines of /var/log/syslog</h3>
<p>How many lines to display? <form action="" method="get">
	<select name="log_count" onchange="this.form.submit()">
		<option value="50" <?php echo ($log_count=='50') ? 'selected':'' ?>>50</option>
		<option value="100" <?php echo ($log_count=='100') ? 'selected':'' ?>>100</option>
		<option value="500" <?php echo ($log_count=='500') ? 'selected':'' ?>>500</option>
</select>
</form></p>
<textarea cols="160" rows="50" wrap="off" readonly="readonly" id="textarea" style="width:99%; font-family:'Courier New', Courier, mono; font-size:11px;background:#E5E5E5;color:#000000;">
<?php
if ($obj[0] != 'none'){
    foreach ($obj as $log){    
		//echo ('<tr><td nowrap>'.date('Y/m/d H:i:s', $alert[2]).'</td>'.'<td nowrap>'.date('Y/m/d H:i:s', $alert[3]).'</td>'.'<td nowrap>'.$alert[7].'</td>'.'<td nowrap>'.$alert[6].'</td>'.'<td>'.str_replace('|','| ',$alert[8]).'</td></tr>');
        echo $log."\r\n";
		}
	}
}

?>
</textarea>

<?php
require 'templates/footer.html';
?>
