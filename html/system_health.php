<?php
session_start();

include_once 'includes/functions.php';

header('Content-Type: application/json');
header('Cache-Control: no-store');

if (login_check() != true){
    http_response_code(403);
    echo json_encode(array('error' => 'Your session has expired. Please log in again.'));
    exit(0);
}

$endpoint = isset($_GET['target']) && $_GET['target'] === 'services' ? 'services' : 'health';
$result = CallAPI('GET', 'http://127.0.0.1:5000/api/v1.0/falcongate/system/' . $endpoint);

if (!$result){
    http_response_code(502);
    echo json_encode(array('error' => 'The Falcongate API process seems to be down.'));
    exit(0);
}

echo $result;
