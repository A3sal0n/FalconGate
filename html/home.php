<?php
session_start();

include_once 'includes/functions.php';
require 'templates/header.html';

?>

<?php

if (login_check() == true){
    require 'home.html';
    require 'templates/footer.html';
 } else {
 echo ("<p><span class=error>You are not authorized to access this page.</span> Please <a href=index.php>login</a>.</p>");
}
?>
