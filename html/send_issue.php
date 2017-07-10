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
<h1>Report Issue</h1>

<?php

$issueID = $_POST['issue_type']. '_' .generateRandomString();

#Check if there is any attachment

if ($_FILES['attachedfile']['error'] != "4"){
    $type = pathinfo($_FILES['attachedfile']['name'], PATHINFO_EXTENSION);
    $data = file_get_contents($_FILES['attachedfile']['tmp_name']);
    $b64 = 'data:image/'. $type .';base64,'.base64_encode($data);
    $unlink = unlink($_FILES['attachedfile']['tmp_name']);
}else{
    $b64 = "";
    $unlink = "";
}

#TO BE DELETED
/*
if (isset($_POST['fg_intel_key'])){
    echo "Issue ID: ".$issueID."<br>";
    echo "User ID: ".$_POST['fg_intel_key']."<br>";
    echo "Description: ".$_POST['description']."<br>";
    echo "Attachment: ".$_FILES['attachedfile']['name']."<br>";
    echo "Attachment type: ".$_FILES['attachedfile']['type']."<br>";
    echo "Attachment size: ".$_FILES['attachedfile']['size']."<br>";
    echo "Count of attached files: ".count($_FILES['attachedfile']['name']);
    echo "<br><br>";

}else{
    echo 'You must have register at FG Threat Intel API to be able report issues.';
}
*/
#Put it all together here

if ($_FILES['attachedfile']['size'] <= 1000000 && isset($_POST['fg_intel_key']) && count($_FILES['attachedfile']['name']) == 1){
    $jsonData = array(
    'issueID' => $issueID,
    'userID' => $_POST['fg_intel_key'],
    'issueDescription' => base64_encode($_POST['description']),
    #'attachment' => base64_encode(file_get_contents(realpath($_FILES['attachedfile']['tmp_name']))));
    'attachment' => $b64);
    #'attachment' => curl_file_create($tmpfile, $_FILES['attachedfile']['type'], $filename));

    $jsonDataEncoded = json_encode($jsonData);
    $fixed_jsonDataEncoded = str_replace("\/", "/", $jsonDataEncoded);
    #echo $fixed_jsonDataEncoded;

    #POST IT TO API
    $ch = curl_init();

    curl_setopt($ch, CURLOPT_URL, "https://2hir4s44b2.execute-api.eu-central-1.amazonaws.com/prod/falcongate-user-feedback/".$issueID.".json");
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $fixed_jsonDataEncoded);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "PUT");

    $headers = array();
    $headers[] = "Content-Length:" . strlen($fixed_jsonDataEncoded);
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
    $unlink;
    

}elseif (empty($_POST['fg_intel_key'])){
    echo '<p><span class=error_message>You must be registered at FG Threat Intel API to be able report issues.</span></p>';
}elseif  ($_FILES['attachedfile']['size'] > 1000000){
    echo "<p><span class=error_message>Maximum size of attachment is 1 MB.</span></p>";
}elseif (count($_FILES['attachedfile']['name']) > 1){
    echo "<p><span class=error_message>Only one file is allowed to attach.</span></p>";
}

?>
