<?php
session_start();

include_once 'includes/functions.php';
require 'templates/header.html';

if (login_check() == true) {
    $logged = 'in';
} else {
    $logged = 'out';
}
?>


<?php
        if (isset($_GET['error'])) {
            echo '<p class="error">Error Logging In!</p>';
        }
        ?>
        <header id="header"><p>Admin login</p></header>
        <br>
        <br>
        <form action="includes/process_login.php" method="post" name="login_form">
            <table style="width:20%;margin-left:20px;">
            <tr align="left">
            <th>Username:</th><th><input type="text" name="uname" /></th>
            </tr>
            <tr align="left">
            <th>Password:</th><th><input type="password" name="passwd" /></th>
            </tr>
            <tr align="left">
            <th><input type="submit" value="Login"></th><th></th>
            </tr>
            </table>
        </form>
        <br>
        <br>

<?php
if (login_check() == true) {
    echo '<p style="margin-left:20px">Currently logged ' . $logged . '.</p>';
        } else {
                        echo '<p style="margin-left:20px">Currently logged ' . $logged . '.</p>';
                }
?>


<?php
require 'templates/footer_index.html';
?>