<?php
session_start();

include_once 'includes/functions.php';

if (login_check() != true){
    echo ("<p><span class=error_message>You are not authorized to access this page. Please</span> <a href=index.php>login</a>.</p>");
    exit(0);
}
require_csrf_token();

if (isset($_POST["update_pwd"])){
    $error = set_admin_password(isset($_POST["pwd"]) ? $_POST["pwd"] : '');
    if ($error !== null){
        echo ("<p><span class=error_message>".htmlspecialchars($error)."</span> <a href=admin.php>Go back</a>.</p>");
        exit(0);
    }
    redirect('admin.php?updated=True');
}

if (isset($_POST["reboot"])){
    echo ("This page will be automatically reloaded in approximately 120 seconds...");
    echo ('<script>
           setTimeout(function(){
           window.location="home.php";
           }, 120000);
           </script>');
    $data = array("action" => "reboot");
    $result = CallAPI('POST', 'http://127.0.0.1:5000/api/v1.0/falcongate/admin/actions', json_encode($data));
}

if (isset($_POST["reset"])){
    echo ("This page will be automatically reloaded in approximately 120 seconds...");
    echo ('<script>
           setTimeout(function(){
           window.location="home.php";
           }, 120000);
           </script>');
    $data = array("action" => "reset");
    $result = CallAPI('POST', 'http://127.0.0.1:5000/api/v1.0/falcongate/admin/actions', json_encode($data));
}
?>

