<?php
session_start();

include_once 'includes/functions.php';

?>

<?php
if (login_check() != true){
    echo ("<p><span class=error_message>You are not authorized to access this page. Please</span> <a href=index.php>login</a>.</p>");
    exit(0);
}
require 'templates/header.html';
?>

<h1>Status</h1>

<?php
$data = array("target" => "network");
$result = CallAPI('POST', 'http://127.0.0.1:5000/api/v1.0/falcongate/status', json_encode($data));
if (!$result){
    echo ("<h3><span class=error_message>FalconGate API process seems to be down!</span></h3>");
    echo ("<h3><span class=error_message>Check your device's configuration and reboot if necessary.</span></h3>");
}else{
    $obj = json_decode($result, true);
    $iface = $obj['interface'];
    $ip = $obj['ip'];
    $gw = $obj['gateway'];
    $netmask = $obj['netmask'];
    $mac = strtoupper($obj['mac']);
    echo ("<h2>FalconGate network configuration</h2>");
    echo ('<table class=TFtable width=98% halign=left>');
    echo ("<tr><td><b>Interface:</b></td><td>".$iface."</td></tr>");
    echo ("<tr><td><b>MAC:</b></td><td>".$mac."</td></tr>");
    echo ("<tr><td><b>IP Address:</b></td><td>".$ip."</td></tr>");
    echo ("<tr><td><b>Default gateway:</b></td><td>".$gw."</td></tr>");
    echo ("<tr><td><b>Network mask:</b></td><td>".$netmask."</td></tr></table>");
    
    $data = array("target" => "devices");
    $result = CallAPI('POST', 'http://127.0.0.1:5000/api/v1.0/falcongate/status', json_encode($data));
    $obj = json_decode($result, true);
    echo ('<br><h2>Active home devices</h2>
    <table class=TFtable width=98% halign=left><tr>
    <td><b>MAC</b></td><td><b>IP Address</b></td><td><b>Vendor</b></td><td><b>Open Ports</b></td></tr>');
    foreach ($obj as $device){
        if ($device['ip'] == $ip){
            echo ('<tr><td>'.$mac.'</td>'.'<td>'.$device['ip'].'</td>'.'<td>FalconGate</td></tr>');
        }else{
            $open_ports = array();
            foreach ($device['tcp_ports'] as $port){
                array_push($open_ports, 'TCP/'.$port);
            }
            foreach ($device['udp_ports'] as $port){
                array_push($open_ports, 'UDP/'.$port);
            }
            echo ('<tr><td>'.strtoupper($device['mac']).'</td>'.'<td>'.$device['ip'].'</td>'.'<td>'.$device['vendor'].'</td>'.'<td>'.implode(', ', $open_ports).'</td></tr>');
        }
    }
    echo ('</table><br>');
}

?>

<?php
require 'templates/footer.html';
?>