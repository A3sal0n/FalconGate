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

<?php
require_once 'Config/Lite.php';
$config = new Config_Lite('user_config.ini', LOCK_EX);
if (isset($_POST['vt_key'])){
    $config->set('main', 'vt_api_key', $_POST['vt_key']);
}
if (isset($_POST['dst_emails'])){
    $config->set('main', 'dst_emails', $_POST['dst_emails']);
}
if (isset($_POST['email_watchlist'])){
    $config->set('main', 'email_watchlist', $_POST['email_watchlist']);
}
if (isset($_POST['blacklist'])){
    $target = explode(",", $_POST['blacklist']);
	$bl_domain_data = array();
	$bl_ip_data = array();
	foreach ($target as $entry){
		if(preg_match("/[a-z][A-Z]/i", $entry)){
			array_push($bl_domain_data, $entry);	
		}else{
			array_push($bl_ip_data, $entry);
		}
	}
	$config->set('main', 'domain_blacklist', implode(",", $bl_domain_data));
	$config->set('main', 'blacklist', implode(",", $bl_ip_data));
	$data = array("action" => "blacklist", "target" => implode(",", $bl_ip_data));
	$result = CallAPI('POST', 'http://127.0.0.1:5000/api/v1.0/falcongate/response/host', json_encode($data));
}
if (isset($_POST['whitelist'])){
    $target = explode(",", $_POST['whitelist']);
	$wl_domain_data = array();
	$wl_ip_data = array();
	foreach ($target as $entry){
		if(preg_match("/[a-z][A-Z]/i", $entry)){
			array_push($wl_domain_data, $entry);	
		}else{
			array_push($wl_ip_data, $entry);
		}
	}
	$config->set('main', 'domain_whitelist', implode(",", $wl_domain_data));
	$config->set('main', 'whitelist', implode(",", $wl_ip_data));
	$data = array("action" => "whitelist", "target" => implode(",", $wl_ip_data));
	$result = CallAPI('POST', 'http://127.0.0.1:5000/api/v1.0/falcongate/response/host', json_encode($data));
}
if (isset($_POST['allow_tor'])){
    $config->set('main', 'allow_tor', 'true');
}else{
    $config->set('main', 'allow_tor', 'false');
}
if (isset($_POST['mailer_address'])){
    $config->set('main', 'mailer_address', $_POST['mailer_address']);
}
if (isset($_POST['mailer_pwd']) and !empty($_POST['mailer_pwd'])){
    //$new_pwd = password_hash($_POST['mailer_pwd'], PASSWORD_DEFAULT);
    $config->set('main', 'mailer_pwd', $_POST['mailer_pwd']);
}
$config->save();
redirect('read_config.php?updated=True');
?>