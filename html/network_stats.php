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
<?php
$data = array("stats_type" => "country", "start_time" => strval(time()-86400), "end_time" => strval(time()));
$result = CallAPI('POST', 'http://127.0.0.1:5000/api/v1.0/falcongate/stats', json_encode($data));
$datapoints_ds = array();
if (!$result){
    echo ("<h3><span class=error_message>FalconGate API process seems to be down!</span></h3>");
    echo ("<h3><span class=error_message>Check your device's configuration and reboot if necessary.</span></h3>");
}else{
	$obj = json_decode($result, true);
	foreach($obj as $cc => $stats) {
        $bs = $stats["bytes_sent"];
        array_push($datapoints_ds, array("label" => $cc, "y" => intval($bs)/1000000));
	}
}
?>
<h1>Network Statistics</h1>
<script>
window.onload = function() {


var chart = new CanvasJS.Chart("chartContainer", {
	animationEnabled: true,
	title: {
		text: "Data sent per country in the last 24hrs"
	},
	subtitles: [{
		text: ""
	}],
	data: [{
		type: "pie",
		yValueFormatString: "##,###0.0000\"MB\"",
		indexLabel: "{label} ({y})",
		dataPoints: <?php echo json_encode($datapoints_ds, JSON_NUMERIC_CHECK); ?>
	}]
});
chart.render();

}
</script>
<div id="chartContainer" style="height: 370px; width: 100%;"></div>
<script src="https://canvasjs.com/assets/script/canvasjs.min.js"></script>

<?php
require 'templates/footer.html';
?>
