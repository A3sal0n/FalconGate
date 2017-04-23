<?php
#session_start();

include_once 'includes/functions.php';

#if (login_check() != true){
#    echo ("<p><span class=error_message>You are not authorized to access this page. Please </span><a href=index.php>login</a>.</p>");
#    exit(0);
#}
if (isset($_POST['handled'], $_POST['id'])){
	$data = array("target" => "alerts_review", "handled" => $_POST['handled'], "alert_id" => $_POST['id']);
	$result = CallAPI('POST', 'http://127.0.0.1:5000/api/v1.0/falcongate/status', json_encode($data));
} else {
	echo "Fail!";
}

?>