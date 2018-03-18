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


<script type='text/javascript'>//<![CDATA[
$(window).load(function(){
$(".show-more a").each(function() {
    var $link = $(this);
    var $content = $link.parent().prev("div.text-content");

    console.log($link);

    var visibleHeight = $content[0].clientHeight;
    var actualHide = $content[0].scrollHeight - 2;

    console.log(actualHide);
    console.log(visibleHeight);

    if (actualHide > visibleHeight) {
        $link.show();
    } else {
        $link.hide();
    }
});

$(".show-more a").on("click", function() {
    var $link = $(this);
    var $content = $link.parent().prev("div.text-content");
    var linkText = $link.text();

    $content.toggleClass("short-text, full-text");

    $link.text(getShowLinkText(linkText));

    return false;
});

function getShowLinkText(currentText) {
    var newText = '';

    if (currentText.toUpperCase() === "SHOW MORE") {
        newText = "Show less";
    } else {
        newText = "Show more";
    }

    return newText;
}
});//]]> 

</script>
<script type="text/javascript">
function submitMe(dbid, handled)
    {
	   variableString = 'id=' + dbid + '&handled=' + handled;
       jQuery.ajax({
       type: "POST",
       url: "alerts_review.php",
       data: variableString,
       success: function(msg){
		 if(handled == 1) {  
			alert( "Event ID " + dbid +" have been reviewed!");
		 } else {
			 alert( "Event ID " + dbid +" have been unreviewed!"); 
		 }
       }
     });
    }

</script>
<script type="text/javascript">
function show_hide_row(row)
{
 $("#"+row).toggle();
}
</script>


<h1>Recent Alerts</h1>

<?php
$period = (!isset($_GET['period'])) ? 'alerts_week': $_GET['period'];
$filter = (!isset($_GET['filter'])) ? 'all': $_GET['filter'];
$data = array("target" => "alerts", "timeframe" => $period, "filter" => $filter);
$result = CallAPI('POST', 'http://127.0.0.1:5000/api/v1.0/falcongate/status', json_encode($data));	
if (!$result){
    echo ("<h3><span class=error_message>FalconGate API process seems to be down!</span></h3>");
    echo ("<h3><span class=error_message>Check your device's configuration and reboot if necessary.</span></h3>");
}else{
    $obj = json_decode($result, true); 
	if ($period == "alerts_week"){
		$display = "last 7 days";
	}elseif ($period == "alerts_month"){
		$display = "last 30 days";
	}else{
		$display = "all time";
	}
?>
	
    <h3>Displaying <?php echo $filter; ?> alerts in <?php echo $display; ?></h3>
    <p align="right"><a href="save-alerts-csv.php?period=<?php echo $period; ?>" target="_blank">download csv</a></p>
	<table width="100%">
	<tbody>
		<tr>
			<td>
				For what period would you like to see alerts? 
				<form action="" method="get">
				<select name="period" onchange="this.form.submit()">
					<option value="alerts_week" <?php echo ($period=='alerts_week') ? 'selected':'' ?>>Last 7 days</option>
					<option value="alerts_month" <?php echo ($period=='alerts_month') ? 'selected':'' ?>>Last 30 days</option>
					<option value="alerts_all" <?php echo ($period=='alerts_all') ? 'selected':'' ?>>All</option>
				</select>
				</form>
			</td>
			<td align="right">	
				<a href="?period=<?php echo $period; ?>&filter=all">All</a> | <a href="?period=<?php echo $period; ?>&filter=reviewed">Reviewed </a>| <a href="?period=<?php echo $period; ?>&filter=notreviewed">Not Reviewed</a>
			</td>
		</tr>
	</tbody>
	</table>
<?php
	
    echo ('<table class=TFtable width=100% halign=left id=table_detail>');
        echo ('<tr>');
			echo ('<td nowrap><b>First seen</b></td><td nowrap><b>Last seen</b></td><td nowrap><b>Host</b></td><td nowrap><b>Threat</b></td><td nowrap><b>Indicators</b></td><td nowrap><b>Is reviewed?</b></td>');
		echo ('</tr>');
		
    if ($obj[0] != 'none'){
		$i = 0;
        foreach ($obj as $alert){
				$i++;
				if ($alert[9] == "0"){
					$checkbox = "<input type=checkbox name=handled id=".$alert[0]." value=0 onclick='submitMe(".$alert[0].", 1);'>";
					$rev = "No";
				}else{
					$checkbox = "<input type=checkbox name=handled id=".$alert[0]." value=1 onclick='submitMe(".$alert[0].", 0);' checked>";
					$rev = "Yes";
				}
            echo ('<tr style="cursor: pointer;" onclick=show_hide_row("hidden_row'.$i.'"); title="Click for more details"><td nowrap>'.date('Y/m/d H:i:s', $alert[2]).'</td>'.'<td nowrap>'.date('Y/m/d H:i:s', $alert[3]).'</td>'.'<td nowrap>'.$alert[7].'</td>'.'<td nowrap>'.$alert[6].'</td>'.'<td><div class="text-content short-text">'.str_replace('|','| ',$alert[8]).'</div><div class="show-more"><a href="#">Show more</a></div></td><td nowrap>'.$checkbox.'</td></tr>');
			echo ('<tr id=hidden_row'.$i.' class=hidden_row><td colspan=6>');
			echo ('<b>Alert ID: </b>'.$alert[0].'<br><b>Threat Category: </b>'.$alert[6].'<br><b>First Seen: </b>'.date('Y/m/d H:i:s', $alert[2]).'<br><b>Last Seen: </b>'.date('Y/m/d H:i:s', $alert[3]).'<br><b>Source IP: </b>'.$alert[7].'<br><b>Alert Indicators: </b>'.str_replace('|','| ',$alert[8]).'<br><b>Alert reviewed? : </b>'.$rev.'<br><b>Alert description :</b>'.$alert[10].'<br><b>VirusTotal Link: </b><a target="_blank" href='.$alert[11].'>'.$alert[11].'</a>');
			echo ('</td></tr>');
        }
    }
    echo ('</table><br>');
   
}

?>

<?php
require 'templates/footer.html';
?>
