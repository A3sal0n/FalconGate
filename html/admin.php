<?php
session_start();

include_once 'includes/functions.php';

?>

<?php
if (login_check() != true){
    echo ("<p><span class=error_message>You are not authorized to access this page. Please </span><a href=index.php>login</a>.</p>");
    exit(0);
}
require 'templates/header.html';
?>

<h1>Administration</h1>

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
        alert("The password you have entered is not enough complex!\n\nThe password must contain lowercase, uppercase, digits and must be longer than 6 characters.");
        return false;
      }

    return true;
  }

  function confirmFormSubmission(){
       return confirm("Do you really want to execute this action?");
  }

</script>

<h3>Admin actions</h3>
    <form name="admin_actions" action="admin_actions.php" method="post" onsubmit="return checkForm();">
           <table width=60% halign=left>
           <tr align=left><td>Set new admin password:</td><td><input type="password" name="pwd" id="pwd" size="20" maxlength="20"></td><td><input class="config_button" type="submit" value="Update" name="update_pwd" id="update_pwd"></form></td></tr>
           </table>

    <br>
    <form name="admin_actions" action="admin_actions.php" method="post" onsubmit="return confirmFormSubmission();">
           <table width=40% halign=left>
           <tr align=left><td>Reboot device:</td><td><input class="config_button" type="submit" value="Reboot" name="reboot"></form></td></tr>
           </table>
    <br>
    <form name="admin_actions" action="admin_actions.php" method="post" onsubmit="return confirmFormSubmission();">
           <table width=35% halign=left>
           <tr align=left><td>Reset Falcongate:</td><td><input class="config_button" type="submit" value="Reset" name="reset"></form></td></tr>
           </table><br>');
if (isset($_GET['updated'])){
    if ($_GET['updated'] == 'True'){
        echo ('<p>Configuration saved!</p><br>');
    }
}
?>
 
<?php
require 'templates/footer.html';
?>