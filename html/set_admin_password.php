<?php
session_start();

include_once 'includes/functions.php';

header('Content-Type: application/json');

if (login_check() != true){
    http_response_code(403);
    echo json_encode(array('error' => 'Your session has expired. Please log in again.'));
    exit(0);
}
require_csrf_token();

$password = isset($_POST['pwd']) ? $_POST['pwd'] : '';
$confirmation = isset($_POST['pwd_confirm']) ? $_POST['pwd_confirm'] : '';

if ($password !== $confirmation){
    $error = 'The passwords do not match.';
}else{
    $error = set_admin_password($password);
}

if ($error !== null){
    http_response_code(400);
    echo json_encode(array('error' => $error));
    exit(0);
}

echo json_encode(array('ok' => true));
