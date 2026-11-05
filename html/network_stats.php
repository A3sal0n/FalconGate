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
<h1>Network Statistics</h1>

<?php
$periods = array(
	'stats_day' => array('seconds' => 86400, 'label' => 'Previous 24 hours'),
	'stats_week' => array('seconds' => 604800, 'label' => 'Previous week'),
	'stats_2week' => array('seconds' => 1209600, 'label' => 'Previous 2 weeks'),
	'stats_month' => array('seconds' => 2592000, 'label' => 'Previous month'),
);
$period = isset($_GET['period']) && is_string($_GET['period']) && isset($periods[$_GET['period']]) ? $_GET['period'] : 'stats_day';
$tframe = $periods[$period]['seconds'];
$period_hint = strtolower($periods[$period]['label']);
$data = array("stats_type" => "country", "start_time" => strval(time()-$tframe), "end_time" => strval(time()));
$result = CallAPI('POST', 'http://127.0.0.1:5000/api/v1.0/falcongate/stats', json_encode($data));
$datapoints_ds_labels = array();
$datapoints_ds_data = array();
$datapoints_dr_labels = array();
$datapoints_dr_data = array();
$datapoints_nc_labels = array();
$datapoints_nc_data = array();

if ($result){
	$obj = json_decode($result, true);
	if (!is_array($obj)){
		$obj = array();
	}

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
	    array_push($datapoints_ds_data, round($bs/1000000,2));
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
	    array_push($datapoints_dr_data, round($br/1000000,2));
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
$has_data = count($datapoints_nc_labels) > 0;

// The top senders, destinations and pairs come from the connections table.
$top_charts = array(
	'senders' => array('id' => 'topSenders', 'title' => 'Top 10 data senders (MB)', 'hint' => 'Known devices on your network'),
	'destinations' => array('id' => 'topDestinations', 'title' => 'Top 10 destination IPs (MB)', 'hint' => 'Internet addresses that received the most data, with their country'),
	'pairs' => array('id' => 'topPairs', 'title' => 'Top 10 connection pairs (MB)', 'hint' => 'Device and Internet address pairs by data sent'),
);
$top_data = array();
$has_top_data = false;
$top_result = false;
if ($result){
	$data['stats_type'] = 'connections';
	$top_result = CallAPI('POST', 'http://127.0.0.1:5000/api/v1.0/falcongate/stats', json_encode($data));
	$top = $top_result ? json_decode($top_result, true) : null;
	foreach ($top_charts as $key => $chart){
		$rows = is_array($top) && isset($top[$key]) ? $top[$key] : array();
		$top_data[$chart['id']] = array('labels' => array(), 'values' => array());
		foreach ($rows as $row){
			array_push($top_data[$chart['id']]['labels'], $row['label']);
			array_push($top_data[$chart['id']]['values'], round($row['bytes']/1000000,2));
			$has_top_data = true;
		}
	}
}
?>

<div class="alerts-toolbar">
	<form id="period_form" action="" method="get">
		<label for="period">Period</label>
		<select id="period" name="period" onchange="this.form.submit()">
			<?php foreach ($periods as $value => $option){ ?>
			<option value="<?php echo $value; ?>" <?php echo $period == $value ? 'selected' : ''; ?>><?php echo $option['label']; ?></option>
			<?php } ?>
		</select>
	</form>
	<button class="config_button stats-refresh" type="submit" form="period_form">Refresh</button>
</div>

<?php if ($result){ ?>
<h2 class="stats-section-title">Traffic by country</h2>
<p class="config-hint">Outbound connections from your devices in the <?php echo $period_hint; ?>, grouped by the destination's country. Statistics are saved every 5 minutes.</p>
<?php } ?>

<?php if (!$result){ ?>
<p class="error_message stats-message">The statistics could not be loaded. The Falcongate API process may be down. Check your device's configuration and reboot if necessary.</p>
<?php }elseif (!$has_data){ ?>
<p class="alerts-empty stats-message">No statistics have been recorded for this period yet. They are saved every 5 minutes while traffic flows.</p>
<?php }else{ ?>
<div class="chart-grid">
	<section class="config-card chart-card">
		<div>
			<h2>Data sent (MB)</h2>
			<p class="config-hint">Top 10 destination countries, <?php echo $period_hint; ?></p>
		</div>
		<div class="chart-canvas">
			<canvas id="countriesDataSent" width="400" height="400"></canvas>
		</div>
	</section>
	<section class="config-card chart-card">
		<div>
			<h2>Data received (MB)</h2>
			<p class="config-hint">Top 10 source countries, <?php echo $period_hint; ?></p>
		</div>
		<div class="chart-canvas">
			<canvas id="countriesDataReceived" width="400" height="400"></canvas>
		</div>
	</section>
	<section class="config-card chart-card">
		<div>
			<h2>Connections</h2>
			<p class="config-hint">Top 10 destination countries, <?php echo $period_hint; ?></p>
		</div>
		<div class="chart-canvas">
			<canvas id="countriesNumConn" width="400" height="400"></canvas>
		</div>
	</section>
</div>

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
  options: {cutoutPercentage: 50, legend: {position: 'left'}}
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
  options: {cutoutPercentage: 50, legend: {position: 'left'}}
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
  options: {cutoutPercentage: 50, legend: {position: 'left'}}
});

}
</script>
<?php } ?>

<?php if ($result){ ?>
<h2 class="stats-section-title">Top connections</h2>
<p class="config-hint">Connections to the Internet that were active in the <?php echo $period_hint; ?>. Each total covers the connection since it was first seen, and connections are kept until 7 days after their last activity.</p>
<?php if (!$top_result){ ?>
<p class="error_message">The top connections could not be loaded.</p>
<?php }elseif (!$has_top_data){ ?>
<p class="alerts-empty">No connections have been recorded for this period yet. They are saved every 5 minutes while traffic flows.</p>
<?php }else{ ?>
<div class="chart-grid chart-grid-wide">
	<?php foreach ($top_charts as $chart){ ?>
	<section class="config-card chart-card">
		<div>
			<h2><?php echo $chart['title']; ?></h2>
			<p class="config-hint"><?php echo $chart['hint']; ?></p>
		</div>
		<div class="chart-canvas" style="height: <?php echo 70 + 30 * count($top_data[$chart['id']]['labels']); ?>px">
			<canvas id="<?php echo $chart['id']; ?>"></canvas>
		</div>
	</section>
	<?php } ?>
</div>

<script>
window.addEventListener("load", function(){
	var charts = <?php echo json_encode($top_data, JSON_HEX_TAG | JSON_HEX_AMP); ?>;
	Object.keys(charts).forEach(function(id){
		new Chart(document.getElementById(id).getContext("2d"), {
			type: "horizontalBar",
			data: {
				labels: charts[id].labels,
				datasets: [{label: "MB sent", data: charts[id].values, backgroundColor: "#1dabb8"}]
			},
			options: {
				legend: {display: false},
				maintainAspectRatio: false,
				scales: {
					xAxes: [{ticks: {beginAtZero: true}, gridLines: {color: "#e3e6e7"}}],
					yAxes: [{
						gridLines: {display: false},
						ticks: {
							// Shorten long axis labels, keeping the IP address. The tooltip shows them in full.
							callback: function(label){
								var limit = window.innerWidth <= 900 ? 24 : 40;
								return label.length > limit ? "…" + label.slice(1 - limit) : label;
							}
						}
					}]
				}
			}
		});
	});
});
</script>
<?php } ?>
<?php } ?>

<?php if ($has_data || $has_top_data){ ?>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/2.9.4/Chart.min.js"></script>
<?php } ?>

<?php
require 'templates/footer.html';
?>
