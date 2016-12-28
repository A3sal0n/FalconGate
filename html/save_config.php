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

<?php
require_once 'Config/Lite.php';

$config = new Config_Lite('user_config.ini', LOCK_EX);

if (isset($_POST['vt_key'])){
    $config->set('main', 'vt_api_key', $_POST['vt_key']);
}

if (isset($_POST['dst_emails'])){
    $config->set('main', 'dst_emails', $_POST['dst_emails']);
}

if (isset($_POST['blacklist'])){
    $config->set('main', 'blacklist', $_POST['blacklist']);
    $target = explode(",", $_POST['blacklist']);
    $data = array("action" => "blacklist", "target" => $target);
    $result = CallAPI('POST', 'http://127.0.0.1:5000/api/v1.0/falcongate/response/host', json_encode($data));
}

if (isset($_POST['whitelist'])){
    $config->set('main', 'whitelist', $_POST['whitelist']);
    $target = explode(",", $_POST['whitelist']);
    $data = array("action" => "whitelist", "target" => $target);
    $result = CallAPI('POST', 'http://127.0.0.1:5000/api/v1.0/falcongate/response/host', json_encode($data));
}

$config->save();

redirect('read_config.php?updated=True');
?>