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
$period = (!isset($_GET['period'])) ? 'stats_day': $_GET['period'];
if($period == 'stats_day') {
	$tframe = 86400;
	$display = "24 hours";
}elseif($period == 'stats_week') {
	$tframe = 604800;
	$display = "1 week";
}elseif($period == 'stats_2week') {
	$tframe = 1209600;
	$display = "2 weeks";
}elseif($period == 'stats_month') {
	$tframe = 2592000;
	$display = "1 month";
}
$data = array("stats_type" => "country", "start_time" => strval(time()-$tframe), "end_time" => strval(time()));
$result = CallAPI('POST', 'http://127.0.0.1:5000/api/v1.0/falcongate/stats', json_encode($data));
$datapoints_ds_labels = array();
$datapoints_ds_data = array();
$datapoints_dr_labels = array();
$datapoints_dr_data = array();
$datapoints_nc_labels = array();
$datapoints_nc_data = array();

if (!$result){
    echo ("<h3><span class=error_message>Falcongate API process seems to be down!</span></h3>");
    echo ("<h3><span class=error_message>Check your device's configuration and reboot if necessary.</span></h3>");
}else{
	$obj = json_decode($result, true);

	// Collecting data sent data points
	$tmp_list = array();
	foreach($obj as $cc => $stats) {
        $bs = $stats["bytes_sent"];
        $tmp_list[$cc] = intval($bs);
        arsort($tmp_list);
	}

	$top10 = array_slice($tmp_list, 0, 10, true);

	foreach($top10 as $cc => $bs) {
	    array_push($datapoints_ds_labels, $cc);
	    array_push($datapoints_ds_data, round($bs/1000,2));
	}

	// Collecting data received data points
	$tmp_list = array();
	foreach($obj as $cc => $stats) {
        $br = $stats["bytes_received"];
        $tmp_list[$cc] = intval($br);
        arsort($tmp_list);
	}

	$top10 = array_slice($tmp_list, 0, 10, true);

	foreach($top10 as $cc => $br) {
	    array_push($datapoints_dr_labels, $cc);
	    array_push($datapoints_dr_data, round($br/1000,2));
	}

	// Collecting connections data points
	$tmp_list = array();
	foreach($obj as $cc => $stats) {
        $nc = $stats["nconn"];
        $tmp_list[$cc] = intval($nc);
        arsort($tmp_list);
	}

	$top10 = array_slice($tmp_list, 0, 10, true);

	foreach($top10 as $cc => $nc) {
	    array_push($datapoints_nc_labels, $cc);
	    array_push($datapoints_nc_data, $nc);
	}
}
?>
<h1>Network Statistics</h1>
<script>
window.onload = function() {
colors = ["rgba(251,128,114,0.8)",
      "rgba(188,128,189,0.8)",
      "rgba(128,177,211,0.8)",
      "rgba(253,180,98,0.8)",
      "rgba(141,211,199,0.8)",
      "rgba(255,255,179,0.8)",
      "rgba(190,186,218,0.8)",
      "rgba(179,222,105,0.8)",
      "rgba(252,205,229,0.8)",
      "rgba(217,217,217,0.8)",
      "rgba(204,235,197,0.8)",
      "rgba(255,237,111,0.8)",
      ];

var ctx_ds = document.getElementById('countriesDataSent').getContext('2d');
var myChart = new Chart(ctx_ds, {
  type: 'pie',
  data: {
    labels: <?php echo json_encode($datapoints_ds_labels); ?>,
    datasets: [{
      label: 'countries',
      data: <?php echo json_encode($datapoints_ds_data); ?>,
      backgroundColor: colors,
    }]
  },
  options: {cutoutPercentage: 50}
});

var ctx_dr = document.getElementById('countriesDataReceived').getContext('2d');
var myChart = new Chart(ctx_dr, {
  type: 'pie',
  data: {
    labels: <?php echo json_encode($datapoints_dr_labels); ?>,
    datasets: [{
      label: 'countries',
      data: <?php echo json_encode($datapoints_dr_data); ?>,
      backgroundColor: colors,
    }]
  },
  options: {cutoutPercentage: 50}
});

var ctx_nc = document.getElementById('countriesNumConn').getContext('2d');
var myChart = new Chart(ctx_nc, {
  type: 'pie',
  data: {
    labels: <?php echo json_encode($datapoints_nc_labels); ?>,
    datasets: [{
      label: 'countries',
      data: <?php echo json_encode($datapoints_nc_data); ?>,
      backgroundColor: colors,
    }]
  },
  options: {cutoutPercentage: 50}
});

}
</script>
<form action="" method="get">
	<select name="period" onchange="this.form.submit()">
	<option value="stats_day" <?php echo ($period=='stats_day') ? 'selected':'' ?>>Previous 24 hours</option>
	<option value="stats_week" <?php echo ($period=='stats_week') ? 'selected':'' ?>>Previous week</option>
	<option value="stats_2week" <?php echo ($period=='stats_2week') ? 'selected':'' ?>>Previous 2 weeks</option>
	<option value="stats_month" <?php echo ($period=='stats_month') ? 'selected':'' ?>>Previous month</option>
	</select>
</form>
				
<div class="container">
  <h2>Data sent in the previous <?php echo $display; ?> (KB) - Top 10 destination countries</h2>
  <div>
    <canvas id="countriesDataSent"></canvas>
  </div>
<br>
  <h2>Data received in the previous <?php echo $display; ?> (KB) - Top 10 source countries</h2>
  <div>
    <canvas id="countriesDataReceived"></canvas>
  </div>
<br>
  <h2>Total number of connections in the previous <?php echo $display; ?> - Top 10 destination countries</h2>
  <div>
    <canvas id="countriesNumConn"></canvas>
  </div>

</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/2.1.4/Chart.min.js"></script>

<?php
require 'templates/footer.html';
?>
