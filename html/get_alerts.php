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

<h1>Recent Alerts</h1>

<?php
$periods = array('alerts_week' => 'Last 7 days', 'alerts_month' => 'Last 30 days', 'alerts_all' => 'All time');
$period_days = array('alerts_week' => 7, 'alerts_month' => 30, 'alerts_all' => null);
$filters = array('all' => 'All', 'notreviewed' => 'Not reviewed', 'reviewed' => 'Reviewed');

$period = isset($_GET['period']) && is_string($_GET['period']) && isset($periods[$_GET['period']]) ? $_GET['period'] : 'alerts_week';
$filter = isset($_GET['filter']) && is_string($_GET['filter']) && isset($filters[$_GET['filter']]) ? $_GET['filter'] : 'all';

$data = array("target" => "alerts", "timeframe" => $period, "filter" => $filter);
$result = CallAPI('POST', 'http://127.0.0.1:5000/api/v1.0/falcongate/status', json_encode($data));

if (!$result){
    echo ("<h3><span class=error_message>Falcongate API process seems to be down!</span></h3>");
    echo ("<h3><span class=error_message>Check your device's configuration and reboot if necessary.</span></h3>");
}else{
    $alerts = json_decode($result, true);
    if (!is_array($alerts) || (isset($alerts[0]) && $alerts[0] === 'none')){
        $alerts = array();
    }
?>

<?php if (count($alerts) > 0){ ?>
<section class="config-card chart-card alerts-chart-card">
    <div>
        <h2>Alerts per day</h2>
        <p class="config-hint"><?php echo $periods[$period]; ?>, by the day each alert was first seen (UTC).<?php echo $filter != 'all' ? ' ' . $filters[$filter] . ' alerts only.' : ''; ?></p>
    </div>
    <div class="chart-canvas chart-canvas-alerts">
        <canvas id="alerts_per_day" role="img" aria-label="Bar chart of the number of alerts per day"></canvas>
    </div>
</section>
<?php } ?>

<div class="alerts-toolbar">
    <form action="" method="get">
        <label for="period">Period</label>
        <select id="period" name="period" onchange="this.form.submit()">
            <?php foreach ($periods as $value => $label){ ?>
            <option value="<?php echo $value; ?>" <?php echo $period == $value ? 'selected' : ''; ?>><?php echo $label; ?></option>
            <?php } ?>
        </select>
        <input type="hidden" name="filter" value="<?php echo $filter; ?>">
    </form>

    <nav class="alerts-filters" aria-label="Filter alerts by review status">
        <?php foreach ($filters as $value => $label){ ?>
        <a href="?period=<?php echo $period; ?>&amp;filter=<?php echo $value; ?>" <?php echo $filter == $value ? 'class="selected" aria-current="true"' : ''; ?>><?php echo $label; ?></a>
        <?php } ?>
    </nav>

    <a class="alerts-download" href="save-alerts-csv.php?period=<?php echo $period; ?>&amp;filter=<?php echo $filter; ?>">Download CSV</a>
</div>

<p class="config-hint">Showing <?php echo count($alerts); ?> <?php echo count($alerts) == 1 ? 'alert' : 'alerts'; ?>. Select a row to see its details.</p>

<?php if (count($alerts) == 0){ ?>
<p class="alerts-empty">No alerts match this selection.</p>
<?php }else{ ?>
<table class="alerts-table" id="alerts_table">
    <thead>
        <tr>
            <th>First seen</th>
            <th>Last seen</th>
            <th>Host</th>
            <th>Threat</th>
            <th>Indicators</th>
            <th>Reviewed</th>
            <th><span class="visually-hidden">Details</span></th>
        </tr>
    </thead>
    <tbody>
    <?php
    foreach ($alerts as $alert){
        $id = (int) $alert[0];
        $indicators = array_filter(array_map('trim', explode('|', (string) $alert[8])), 'strlen');
        $reference = (string) $alert[11];
        $reviewed = $alert[9] != 0;
    ?>
        <tr class="alert-row">
            <td data-label="First seen" class="alert-time"><?php echo esc_html($alert[2]); ?></td>
            <td data-label="Last seen" class="alert-time"><?php echo esc_html($alert[3]); ?></td>
            <td data-label="Host" class="alert-host"><?php echo esc_html($alert[7]); ?></td>
            <td data-label="Threat"><span class="alert-threat"><?php echo esc_html($alert[6]); ?></span></td>
            <td data-label="Indicators"><div class="alert-indicators"><?php echo esc_html(implode(' | ', $indicators)); ?></div></td>
            <td data-label="Reviewed"><input type="checkbox" class="alert-reviewed" data-alert-id="<?php echo $id; ?>" aria-label="Mark alert <?php echo $id; ?> as reviewed" <?php echo $reviewed ? 'checked' : ''; ?>></td>
            <td class="alert-toggle"><button type="button" class="alert-details-button" aria-expanded="false" aria-controls="alert_details_<?php echo $id; ?>">Details</button></td>
        </tr>
        <tr class="alert-details" id="alert_details_<?php echo $id; ?>" hidden>
            <td colspan="7">
                <dl>
                    <dt>Alert ID</dt><dd><?php echo $id; ?></dd>
                    <dt>Threat category</dt><dd><?php echo esc_html($alert[6]); ?></dd>
                    <dt>Source</dt><dd><?php echo esc_html($alert[7]); ?></dd>
                    <dt>First seen</dt><dd><?php echo esc_html($alert[2]); ?></dd>
                    <dt>Last seen</dt><dd><?php echo esc_html($alert[3]); ?></dd>
                    <dt>Indicators</dt>
                    <dd>
                        <ul>
                            <?php foreach ($indicators as $indicator){ ?>
                            <li><?php echo esc_html($indicator); ?></li>
                            <?php } ?>
                        </ul>
                    </dd>
                    <dt>Description</dt><dd><?php echo esc_html(strip_tags((string) $alert[10])); ?></dd>
                    <dt>Reference</dt>
                    <dd>
                        <?php if (preg_match('#^https?://#i', $reference)){ ?>
                        <a href="<?php echo esc_html($reference); ?>" target="_blank" rel="noopener noreferrer"><?php echo esc_html($reference); ?></a>
                        <?php }else{ echo esc_html($reference); } ?>
                    </dd>
                </dl>
            </td>
        </tr>
    <?php } ?>
    </tbody>
</table>

<script>
(function(){
    var table = document.getElementById("alerts_table");
    var csrfToken = <?php echo json_encode(csrf_token()); ?>;

    // Select a row, or its Details button, to show or hide the details below it.
    table.addEventListener("click", function(event){
        var row = event.target.closest(".alert-row");
        if (!row || event.target.closest("input, a")) {
            return;
        }
        var button = row.querySelector(".alert-details-button");
        var details = document.getElementById(button.getAttribute("aria-controls"));
        details.hidden = !details.hidden;
        button.setAttribute("aria-expanded", String(!details.hidden));
        button.textContent = details.hidden ? "Details" : "Hide";
    });

    table.addEventListener("change", function(event){
        var checkbox = event.target;
        if (!checkbox.classList.contains("alert-reviewed")) {
            return;
        }
        var body = new URLSearchParams();
        body.append("id", checkbox.getAttribute("data-alert-id"));
        body.append("handled", checkbox.checked ? "1" : "0");
        body.append("csrf_token", csrfToken);

        checkbox.disabled = true;
        fetch("alerts_review.php", {method: "POST", body: body, credentials: "same-origin"})
            .then(function(response){
                if (!response.ok) {
                    throw new Error("Request failed");
                }
            })
            .catch(function(){
                checkbox.checked = !checkbox.checked;
                alert("The alert could not be updated. Reload the page and try again.");
            })
            .then(function(){
                checkbox.disabled = false;
            });
    });
})();
</script>

<script src="scripts/chart-4.6.1.umd.min.js"></script>
<script>
(function(){
    var days = <?php echo json_encode(count_alerts_per_day($alerts, $period_days[$period]), JSON_HEX_TAG | JSON_HEX_AMP); ?>;

    new Chart(document.getElementById("alerts_per_day").getContext("2d"), {
        type: "bar",
        data: {
            labels: days.map(function(day){ return day.label; }),
            datasets: [{
                label: "Alerts",
                data: days.map(function(day){ return day.count; }),
                backgroundColor: "#1dabb8",
                borderRadius: 4,
                maxBarThickness: 48
            }]
        },
        options: {
            maintainAspectRatio: false,
            // Hovering anywhere above a day shows its count, including days with no bar to point at.
            interaction: {mode: "index", intersect: false},
            plugins: {
                legend: {display: false},
                tooltip: {
                    displayColors: false,
                    callbacks: {
                        // The axis leaves out the year, so the tooltip gives the full date.
                        title: function(items){ return days[items[0].dataIndex].date; }
                    }
                }
            },
            scales: {
                x: {grid: {display: false}, ticks: {maxRotation: 0, autoSkipPadding: 12}},
                y: {beginAtZero: true, grid: {color: "#e3e6e7"}, ticks: {precision: 0}}
            }
        }
    });
})();
</script>
<?php
    }
}
?>

<?php
require 'templates/footer.html';
?>
