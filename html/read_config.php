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
<h1>Configuration</h1>

<?php
require_once 'Config/Lite.php';
$config = new Config_Lite('user_config.ini');
$standalone = '';
$gmail = '';
                
if($config['main']['mailer_mode'] == 'standalone'){
    $status = 'disabled';
    $standalone = 'selected';
}else{
    $status = '';
    $gmail = 'selected';
}
    echo ('<form name="user_config" id="user_config" action="save_config.php" onsubmit="return ValidateInput();" method="post">
           <table width=95% halign=left>
           <tr align=left><td title="Your personal VirusTotal API key.">VirusTotal API key:</td><td><input type=text size=71 name="vt_key" value='.$config['main']['vt_api_key'].'></td></tr>
           <tr align=left><td title="This is the list of recipients for the email alerts sent by FalconGate.">Alert recipients:</td><td><input type=text size=71 name="dst_emails" value='.$config['main']['dst_emails'].'></td></tr>
           <tr align=left><td title="This is the customized list of IP addresses you wish to block.">Blacklist:</td><td><textarea form="user_config" id="blacklist" name="blacklist" rows=5 cols=81>'.$config['main']['blacklist'].'</textarea></td></tr>
           <tr align=left><td title="This is the list of IP addresses to be whitelisted from blocking by FalconGuard.">Whitelist:</td><td><textarea form="user_config" id="whitelist" name="whitelist" rows=5 cols=81>'.$config['main']['whitelist'].'</textarea></td></tr>
           <tr align=left><td title="This is the list of email addresses to be monitored for potential compromise due to hacking breaches in third party online services.">Email watchlist:</td><td><textarea form="user_config" id="email_watchlist" name="email_watchlist" rows=5 cols=81>'.$config['main']['email_watchlist'].'</textarea></td></tr>
           </table>
           <input class="config_button" type="submit" value="Save">
           </form><br>');
echo ('<p class=notes>Note: Multiple recipient emails can be added to the "Alerts recipients" field using commas as separator.</p><br>');
    echo ("<p><i><b>Select below your preferred option for alerting (default = Standalone):</b></i></p>");
    echo ('<form name="from_email" id="from_email" action="save_config.php" onsubmit="return ValidateMailerInput();" method="post">
           <table>
           <td>
           <select name="selector" id="selector" onchange="if (document.getElementById(\'selector\').value == \'gmail\'){document.getElementById(\'mailer_address\').disabled = \'\';document.getElementById(\'mailer_pwd\').disabled = \'\';}else {document.getElementById(\'mailer_address\').disabled = \'true\';document.getElementById(\'mailer_pwd\').disabled = \'true\';}">
           <option value="standalone" '.$standalone.'>Standalone</option>
           <option value="gmail" '.$gmail.'>Gmail</option>
           </td>
           </table>
           <table width=40% halign=left>
           <tr align=left><td>Gmail address:</td><td><input type=text size=20 name="mailer_address" id="mailer_address" '.$status.'  value='.$config['main']['mailer_address'].'></td></tr>
           <tr align=left><td>Password:</td><td><input type="password" name="mailer_pwd" id="mailer_pwd" size="20" maxlength="500" '.$status.'></td></tr>
           </table>
           <input class="config_button" type="submit" value="Save" name="mailer_submit" id="mailer_submit">
           </form>');
if (isset($_GET['updated'])){
    if ($_GET['updated'] == 'True'){
        echo ('<p>Configuration saved!</p>
        <p>FalconGate process restarted...</p>');
    }
}
?>
 
<?php
require 'templates/footer.html';
?>