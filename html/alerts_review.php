<?php
session_start();

include_once 'includes/functions.php';

if (login_check() != true){
    http_response_code(403);
    echo ("<p><span class=error_message>You are not authorized to access this page. Please </span><a href=index.php>login</a>.</p>");
    exit(0);
}
require_csrf_token();
if (isset($_POST['handled'], $_POST['id'])){
	$data = array("target" => "alerts_review", "handled" => $_POST['handled'], "alert_id" => $_POST['id']);
	$result = CallAPI('POST', 'http://127.0.0.1:5000/api/v1.0/falcongate/status', json_encode($data));
	$response = json_decode((string) $result, true);
	if (!is_array($response) || empty($response['updated'])) {
		http_response_code(502);
		echo "Fail!";
	}
} else {
	http_response_code(400);
	echo "Fail!";
}

?>