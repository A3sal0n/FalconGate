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

<h1>Recent Alerts</h1>

<?php
$period = (!isset($_GET['period'])) ? 'alerts_week': $_GET['period'];
$data = array("target" => "alerts", "timeframe" => $period);
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
	
    <h3>Alerts detected in <?php echo $display; ?></h3>
    <p align="right"><a href="save-alerts-csv.php?period=<?php echo $period; ?>" target="_blank">download csv</a></p>
	<p>For what period would you like to see alerts? <form action="" method="get">
	<select name="period" onchange="this.form.submit()">
		<option value="alerts_week" <?php echo ($period=='alerts_week') ? 'selected':'' ?>>Last 7 days</option>
		<option value="alerts_month" <?php echo ($period=='alerts_month') ? 'selected':'' ?>>Last 30 days</option>
		<option value="alerts_all" <?php echo ($period=='alerts_all') ? 'selected':'' ?>>All</option>
	</select>
	</form></p>
<?php	
    echo ('<table class=TFtable width=100% halign=left>');
        echo ('<tr>');
			echo ('<td nowrap><b>First seen</b></td><td nowrap><b>Last seen</b></td><td nowrap><b>Host</b></td><td nowrap><b>Threat</b></td><td nowrap><b>Indicators</b></td>');
		echo ('</tr>');
		
    if ($obj[0] != 'none'){
        foreach ($obj as $alert){    
            echo ('<tr><td nowrap>'.date('Y/m/d H:i:s', $alert[2]).'</td>'.'<td nowrap>'.date('Y/m/d H:i:s', $alert[3]).'</td>'.'<td nowrap>'.$alert[7].'</td>'.'<td nowrap>'.$alert[6].'</td>'.'<td><div class="text-content short-text">'.str_replace('|','| ',$alert[8]).'</div><div class="show-more"><a href="#">Show more</a></div></td></tr>');
        }
    }
    echo ('</table>');
   
}

?>

<?php
require 'templates/footer.html';
?>
