<?php
ini_set('display_errors', 1); error_reporting(E_ALL);
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

<script type='text/javascript'>
function torAlert() {
    if (document.getElementById('allow_tor').checked) {
        alert("Are you sure you want to allow Tor in your network? Malware can use Tor to hide its traffic!");
    }
}

function cloudScanAlert() {
    if (document.getElementById('enable_cloud_scan').checked == false) {
        return true;
      } else {
       var box= confirm("By selecting this option, you agree with our Terms of Service and that you have read our Privacy Policy");
        if (box==true)
            return true;
        else
           document.getElementById('enable_cloud_scan').checked = false;

      }
}

</script>

<?php
require_once 'Config/Lite.php';
$config = new Config_Lite('user_config.ini');
?>

<?php
    if ($config['main']['allow_tor'] == 'true'){
        $tor_value = "value=1 checked=checked";
    }else{
        $tor_value = "value=0";
    }
    echo ('<form name="user_config" id="user_config" action="save_config.php" onsubmit="return ValidateInput();" method="post">
           <table width=95% halign=left>
           <tr align=left><td width=300 title="Your personal VirusTotal API key.">VirusTotal API key:</td><td><input type=text size=71 name="vt_key" value='.$config['main']['vt_api_key'].'></td></tr>
           <tr align=left><td width=300 title="This is the list of recipients for the email alerts sent by Falcongate.">Alert recipients:</td><td><input type=text size=71 name="dst_emails" value='.$config['main']['dst_emails'].'></td></tr>
           <tr align=left><td width=300 title="This is the customized list of IP addresses and domains you wish to block.">Blacklist:</td><td><textarea form="user_config" id="blacklist" name="blacklist" rows=5 cols=81>'.$config['main']['blacklist'].''.$config['main']['domain_blacklist'].'</textarea></td></tr>
           <tr align=left><td width=300 title="This is the list of IP addresses and domains to be whitelisted from blocking by FalconGuard.">Whitelist:</td><td><textarea form="user_config" id="whitelist" name="whitelist" rows=5 cols=81>'.$config['main']['whitelist'].''.$config['main']['domain_whitelist'].'</textarea></td></tr>
           <tr align=left><td width=300 title="This is the list of email addresses to be monitored for potential compromise due to hacking breaches in third party online services.">Email watchlist:</td><td><textarea form="user_config" id="email_watchlist" name="email_watchlist" rows=5 cols=81>'.$config['main']['email_watchlist'].'</textarea></td></tr>
           <tr align=left><td width=300 title="Enter the Gmail address from where the Falcongate alerts will be send.">Gmail Address:</td><td><input type=text size=20 name="mailer_address" id="mailer_address" value='.$config['main']['mailer_address'].'></td></tr>
		   <tr align=left><td width=300 title="Enter the password for Gmail address from where the Falcongate alerts will be send.">Gmail Password:</td><td><input type="password" name="mailer_pwd" id="mailer_pwd" size="20" maxlength="500"></td></tr>
           <tr align=left><td width=300 title="Allow traffic towards the Tor network." colspan=2>Allow Tor <input type=checkbox name=allow_tor id=allow_tor value='.$tor_value.' onchange="torAlert()"</td></tr>
           </table>
           <br>');
    echo ('<p class=notes>Note: Multiple recipient emails can be added to the "Alerts recipients" field using commas as separator.</p>');
    echo ('<br><input class="config_button" type="submit" value="Save" name="mailer_submit" id="mailer_submit"></form>');
if (isset($_GET['updated'])){
    if ($_GET['updated'] == 'True'){
        echo ('<p>Configuration saved!</p>
        <p>Falcongate process restarted...</p>');
    }
}
?>
 
<?php
require 'templates/footer.html';
?>