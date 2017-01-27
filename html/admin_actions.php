<?php
session_start();

include_once 'includes/functions.php';

if (login_check() != true){
    echo ("<p><span class=error_message>You are not authorized to access this page. Please</span> <a href=index.php>login</a>.</p>");
    exit(0);
}

if (isset($_POST["update_pwd"])){
//    echo ("form detected");
    $new_pwd = password_hash($_POST["pwd"], PASSWORD_DEFAULT);
    $myfile = fopen("./pwd.db", "w") or die("Unable to open file!");
    fwrite($myfile, "admin ".$new_pwd);
    fclose($myfile);
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
?>

