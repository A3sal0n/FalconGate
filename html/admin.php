<?php
session_start();

include_once 'includes/functions.php';
require 'templates/header.html';

?>

<?php
if (login_check() != true){
    echo ("<p><span class=error>You are not authorized to access this page.</span> Please <a href=index.php>login</a>.</p>");
    exit(0);
}
?>

	<header id="header"><h1>FalconGate</h1></header>

	<div id="container">

		<main id="center" class="column">
			<article>

<?php

echo ('<script type="text/javascript">

  function checkPassword(str)
  {
    var re = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}$/;
    return re.test(str);
  }

  function checkForm(form)
  {
  var pwd = document.forms["admin_actions"]["pwd"].value;
      if(!checkPassword(pwd)) {
        alert("The password you have entered is not valid!\n\nThe password must contain lowercase, uppercase, digits and must be longer than 6 characters.");
        return false;
      }

    return true;
  }

</script>

<h3>Admin actions</h3>
    <form name="admin_actions" action="admin_actions.php" method="post" onsubmit="return checkForm();">
           <table width=35% halign=left>
           <tr align=left><td>Set new admin password:</td><td><input type="password" name="pwd" id="pwd" size="15" maxlength="20"></td><td><input type="submit" value="Update" name="update_pwd" id="update_pwd"></form></td></tr>
           </table>

    <br>
    <form name="admin_actions" action="admin_actions.php" method="post">
           <table width=15% halign=left>
           <tr align=left><td>Reboot device</td><td><input type="submit" value="Reboot" name="reboot"></form></td></tr>
           </table>');
if (isset($_GET['updated'])){
    if ($_GET['updated'] == 'True'){
        echo ('<p>Configuration saved!</p>');
    }
}
?>
 
<?php
require 'templates/footer.html';
?>