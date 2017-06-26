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
<h1>Report Issue</h1>

<?php
require_once 'Config/Lite.php';
$config = new Config_Lite('user_config.ini');
$standalone = '';
$gmail = '';
                
if(strlen($config['main']['fg_intel_key']) == 40){
    $fg_intel_key = $config['main']['fg_intel_key'];

}else{
    $fg_intel_key = '';
}

    echo ('<form name="report_issue" id="report_issue" action="send_issue.php" onsubmit="return ValidateInput();" method="post" enctype="multipart/form-data">
          <table width=95% halign=left>
            <tr align=left>
              <td title="Select type of issue you have.">Type of Issue:</td>
              <td>
                <select name="issue_type">
                  <option value="Web_Interface">Web Interface</option>
                  <option value="System">System</option>
                  <option value="Improvement">Improvement</option>
                  <option value="Other">Other</option>
                </select>
              </td>
            </tr>
            <tr align=left>
              <td title="Description of your issue. Please provide as much details possible.">Description:</td>
              <td><textarea form="report_issue" id="desc" name="description" rows=5 cols=81></textarea></td>
            </tr>
            <tr align=left>
              <td title="Attach screenshot or any other evidence. Max file size is 400kB">Attachment:</td>
              <td>
                <input type="file" name="attachedfile">
                <input type="hidden" name="fg_intel_key" value="'.$fg_intel_key.'">
              </td>
            </tr>
          </table>
          <input class="config_button" type="submit" value="Submit">
           </form><br>');
?>
 
<?php
require 'templates/footer.html';
?>