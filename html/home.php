<?php
session_start();

include_once 'includes/functions.php';

?>

<?php

if (login_check() == true){
	require 'templates/header.html';
    require 'home.html';
    require 'templates/footer.html';
 } else {
 echo ("<p><span class=error>You are not authorized to access this page.</span> Please <a href=index.php>login</a>.</p>");
}
?>
