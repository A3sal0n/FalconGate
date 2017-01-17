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

if (isset($_POST['selector'])){
    if($_POST['selector'] == 'gmail'){
        $config->set('main', 'mailer_mode', $_POST['selector']);
        if (isset($_POST['mailer_address'])){
            $config->set('main', 'mailer_address', $_POST['mailer_address']);
        }
        
        if (isset($_POST['mailer_pwd']) and !empty($_POST['mailer_pwd'])){
            //$new_pwd = password_hash($_POST['mailer_pwd'], PASSWORD_DEFAULT);
            $config->set('main', 'mailer_pwd', $_POST['mailer_pwd']);
        }
    }else{
        $config->set('main', 'mailer_mode', $_POST['selector']);
        $config->set('main', 'mailer_address', '');
        $config->set('main', 'mailer_pwd', '');
    }
}


$config->save();

redirect('read_config.php?updated=True');
?>