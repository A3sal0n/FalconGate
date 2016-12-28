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
require_once 'Config/Lite.php';

$config = new Config_Lite('user_config.ini');

echo ("<h3>User configuration</h3>");
    echo ('<form name="user_config" id="user_config" action="save_config.php" onsubmit="return ValidateInput();" method="post">
           <table width=60% halign=left>
           <tr align=left><td>VirusTotal API key:</td><td><input type=text size=70 name="vt_key" value='.$config['main']['vt_api_key'].'></td></tr>
           <tr align=left><td>Alert recipients:</td><td><input type=text size=70 name="dst_emails" value='.$config['main']['dst_emails'].'></td></tr>
           <tr align=left><td>Blacklist:</td><td><textarea form="user_config" id="blacklist" name="blacklist" rows=5 cols=70>'.$config['main']['blacklist'].'</textarea></td></tr>
           <tr align=left><td>Whitelist:</td><td><textarea form="user_config" id="whitelist" name="whitelist" rows=5 cols=70>'.$config['main']['whitelist'].'</textarea></td></tr>
           </table>
           <input type="submit" value="Save">
           </form>');

echo ('<p>Note: Multiple recipient emails can be added to the "Alerts recipients" field using commas as separator</p>');
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