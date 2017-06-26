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
ini_set('display_errors', 1);

$issueID = $_POST['issue_type']. '_' .generateRandomString();
$type = pathinfo($_FILES['attachedfile']['name'], PATHINFO_EXTENSION);
$data = file_get_contents($_FILES['attachedfile']['tmp_name']);
$b64 = 'data:image/'. $type .';base64,'.base64_encode($data);


if (isset($_POST['fg_intel_key'])){
    echo "Issue ID: ".$issueID."<br>";
    echo "User ID: ".$_POST['fg_intel_key']."<br>";
    echo "Description: ".$_POST['description']."<br>";
    echo "Attachment: ".$_FILES['attachedfile']['name']."<br>";
    echo "Attachment type: ".$_FILES['attachedfile']['type'];
    echo "<br><br>";

}else{
    echo 'You must have register at FG Threat Intel API to be able report issues.';
}

if (filesize($_FILES['attachedfile']['tmp_name']) <= 400000 || isset($_POST['fg_intel_key'])){
    $jsonData = array(
    'issueID' => $issueID,
    'userID' => $_POST['fg_intel_key'],
    'issueDescription' => base64_encode($_POST['description']),
    #'attachment' => base64_encode(file_get_contents(realpath($_FILES['attachedfile']['tmp_name']))));
    'attachment' => $b64);
    #'attachment' => curl_file_create($tmpfile, $_FILES['attachedfile']['type'], $filename));

    $jsonDataEncoded = json_encode($jsonData);

    echo $jsonDataEncoded;

    #POST IT TO API
    $ch = curl_init();

    curl_setopt($ch, CURLOPT_URL, "https://2hir4s44b2.execute-api.eu-central-1.amazonaws.com/dev1/falcongate-user-feedback/".$issueID.".json");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $jsonDataEncoded);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "PUT");

    $headers = array();
    $headers[] = "Content-Length:" . strlen($jsonDataEncoded);
    $headers[] = "X-Api-Key:" .$_POST['fg_intel_key'];
    $headers[] = "Content-Type: application/json";
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

    $result = curl_exec($ch);
    if (curl_errno($ch)) {
        echo 'Error:' . curl_error($ch);
    }else{
        echo "<br><br>Thank you for reporting this to us. We will take a look at it and contact you if neccesary."; 
    }
    curl_close ($ch);
    unlink($_FILES['attachedfile']['tmp_name']);

}elseif (empty($_POST['fg_intel_key'])){
    echo 'You must have register at FG Threat Intel API to be able report issues.';
}elseif  (filesize($_FILES['attachedfile']['tmp_name']) > 400000){
    echo "Maximum size of attachment is 400kB.";
}

?>