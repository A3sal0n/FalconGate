<?php
session_start();
unset($_SESSION["ID"]);
header("Location: index.php");
?>