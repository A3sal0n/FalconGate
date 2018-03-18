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

<script type="text/javascript">
function show_hide_row(row)
{
 $("#"+row).toggle();
}
</script>

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
    <table class=TFtable width=98% halign=left id=table_detail><tr>
    <td><b>Hostname</b></td><td><b>MAC</b></td><td><b>IP Address</b></td><td><b>Vendor</b></td><td><b>Details</b></td></tr>');
    $i = 0;
	foreach ($obj as $device){
		$i++;
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
            echo ('<tr style="cursor: pointer;" onclick=show_hide_row("hidden_row'.$i.'");><td>'.$device['hostname'].'</td>'.'<td>'.strtoupper($device['mac']).'</td>'.'<td>'.$device['ip'].'</td>'.'<td>'.$device['vendor'].'</td>'.'<td><a href="#" onclick=show_hide_row("hidden_row'.$i.'");">Show more</a></td></tr>');
			echo ('<tr id=hidden_row'.$i.' class=hidden_row><td colspan=5>');
			echo ('<b>Hostname:</b> '.$device['hostname'].'<br><b>MAC Address: </b>'.$device['mac'].'<br><b>IP Address: </b>'.$device['ip'].'<br><b>Vendor: </b>'.$device['vendor'].'<br><b>Open Ports: </b>'.implode(', ', $open_ports).'');			
			echo ('</td></tr>');
			
        }
    }
    echo ('</table><br>');
}

?>

<?php
require 'templates/footer.html';
?>
