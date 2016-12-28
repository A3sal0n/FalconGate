<?php
session_start();

include_once 'functions.php';

if (isset($_POST['uname'], $_POST['passwd'])) {
    $uname = $_POST['uname'];
    $password = $_POST['passwd'];

    if (login($uname, $password) == true) {
        // Login success
        header('Location: ../home.php');
    } else {
        // Login failed
        header('Location: ../index.php?error=1');
    }
} else {
    echo 'Invalid Request';
}

?>