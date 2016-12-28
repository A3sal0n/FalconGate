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
$data = array("target" => "network");
$result = CallAPI('POST', 'http://127.0.0.1:5000/api/v1.0/falcongate/status', json_encode($data));
if (!$result){
    echo ("<h3>FalconGate API process seems to be down!</h3>");
    echo ("<h3>Check your device's configuration and reboot if necessary.</h3>");
}else{
    $obj = json_decode($result, true);
    $iface = $obj['interface'];
    $ip = $obj['ip'];
    $gw = $obj['gateway'];
    $netmask = $obj['netmask'];
    $mac = strtoupper($obj['mac']);
    echo ("<h3>FalconGate network configuration</h3>");
    echo ('<table class=TFtable width=40% halign=left>');
    echo ("<tr><td><b>Interface:</b></td><td>".$iface."</td></tr>");
    echo ("<tr><td><b>MAC:</b></td><td>".$mac."</td></tr>");
    echo ("<tr><td><b>IP Address:</b></td><td>".$ip."</td></tr>");
    echo ("<tr><td><b>Default gateway:</b></td><td>".$gw."</td></tr>");
    echo ("<tr><td><b>Network mask:</b></td><td>".$netmask."</td></tr></table>");
    
    $data = array("target" => "devices");
    $result = CallAPI('POST', 'http://127.0.0.1:5000/api/v1.0/falcongate/status', json_encode($data));
    $obj = json_decode($result, true);
    echo ('<br><h3>Active home devices</h3>
    <table class=TFtable width=40% halign=left><tr>
    <td><b>MAC</b></td><td><b>IP Address</b></td><td><b>Vendor</b></td></tr>');
    foreach ($obj as $device){
        if ($device['ip'] == $ip){
            echo ('<tr><td>'.$mac.'</td>'.'<td>'.$device['ip'].'</td>'.'<td>FalconGate</td></tr>');
        }else{
            echo ('<tr><td>'.strtoupper($device['mac']).'</td>'.'<td>'.$device['ip'].'</td>'.'<td>'.$device['vendor'].'</td></tr>');
        }
    }
    echo ('</table>');
}

?>

<?php
require 'templates/footer.html';
?>