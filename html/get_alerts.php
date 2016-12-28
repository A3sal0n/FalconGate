<?php
session_start();

include_once 'includes/functions.php';
require 'templates/header.html';

?>

<?php
if (login_check() != true){
    echo ("<p><span class=error>You are not authorized to access this page.</span> Please <a href=index.php>login</a>.</p>");
    exit(0);
}
?>

	<header id="header"><h1>FalconGate</h1></header>

	<div id="container">

		<main id="center" class="column">
			<article>

<?php
$data = array("target" => "alerts");
$result = CallAPI('POST', 'http://127.0.0.1:5000/api/v1.0/falcongate/status', json_encode($data));
if (!$result){
    echo ("<h3>FalconGate API process seems to be down!</h3>");
    echo ("<h3>Check your device's configuration and reboot if necessary.</h3>");
}else{
    $obj = json_decode($result, true);
    echo ("<h3>Alerts detected in the previous week</h3>");
    echo ("<p align=right><a href=save-alerts-csv.php target=_blank>download csv</a></p>");
    echo ('<table class=TFtable width=100% halign=left>
        <tr><td><b>First seen</b></td><td><b>Last seen</b></td><td><b>Host</b></td><td><b>Threat</b></td><td><b>Indicators</b></td></tr>');
    if ($obj[0] != 'none'){
        foreach ($obj as $alert){    
            echo ('<tr><td>'.date('Y/m/d H:i:s', $alert['alerts']['first_seen']).'</td>'.'<td>'.date('Y/m/d H:i:s', $alert['alerts']['last_seen']).'</td>'.'<td>'.$alert['host'].'</td>'.'<td>'.$alert['alerts']['threat'].'</td>'.'<td>'.implode(",", $alert['alerts']['indicators']).'</td></tr>');
        }
    }
    echo ('</table>');
    
}

?>

<?php
require 'templates/footer.html';
?>