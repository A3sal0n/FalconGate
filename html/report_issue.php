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
<script type="text/javascript">
function ValidateSize(file) {
        var FileSize = file.files[0].size / 1024 / 1024; // in MB
        if (FileSize > 1) {
            alert('File size exceeds 1 MB');
           $(file).val(''); //Clear the file
        } else {

        }
    }
</script>
<h1>Report Issue</h1>

<?php
require_once 'Config/Lite.php';
$config = new Config_Lite('user_config.ini');
                
if(strlen($config['main']['fg_intel_key']) == 40){
    $fg_intel_key = $config['main']['fg_intel_key'];
    $disabled = "";
    $message = "";

}else{
    $fg_intel_key = '';
    $disabled = 'disabled="disabled"';
    $message = '<p><span class=error_message>You must be registered at FG Threat Intel API to be able report issues.</span></p><br>';
}

  echo ($message.'<form name="report_issue" id="report_issue" action="send_issue.php" method="post" enctype="multipart/form-data">
          <table width=95% halign=left>
            <tr align=left>
              <td title="Select type of issue you have.">Type of Issue:</td>
              <td>
                <select name="issue_type" '.$disabled.'>
                  <option value="Web_Interface">Web Interface</option>
                  <option value="System">System</option>
                  <option value="Improvement">Improvement</option>
                  <option value="Other">Other</option>
                </select>
              </td>
            </tr>
            <tr align=left>
              <td title="Description of your issue. Please provide as much details possible.">Description:</td>
              <td><textarea form="report_issue" id="description" name="description" rows=5 cols=81 required '.$disabled.'></textarea></td>
            </tr>
            <tr align=left>
              <td title="Attach screenshot or any other evidence. Max file size is 1 MB">Attachment:</td>
              <td>
                <input type="file" name="attachedfile" id="attachment" onchange="ValidateSize(this)" '.$disabled.'>
                <input type="hidden" name="fg_intel_key" value="'.$fg_intel_key.'">
              </td>
            </tr>
          </table>
          <input class="config_button" type="submit" value="Submit" '.$disabled.'>
           </form><br>');
   
?>
 
<?php
require 'templates/footer.html';
?>