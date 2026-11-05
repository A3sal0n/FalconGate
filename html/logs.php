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
<h1>System Overview</h1>

<div class="config-page">
    <section class="config-card" id="system_health" data-url="system_health.php">
        <h2>Server health</h2>
        <p class="config-hint health-state" id="health_state" role="status">Loading server health...</p>
        <div class="health-tiles" id="health_tiles"></div>

        <h3 class="health-subheading">Disk partitions</h3>
        <div class="health-disks" id="health_disks"></div>
    </section>

    <section class="config-card">
        <h2>System logs</h2>
<?php
$log_counts = array('50', '100', '500');
$log_count = isset($_GET['log_count']) && in_array($_GET['log_count'], $log_counts, true) ? $_GET['log_count'] : '50';
?>
        <form class="log-toolbar" action="" method="get">
            <label for="log_count">Entries to show</label>
            <select id="log_count" name="log_count" onchange="this.form.submit()">
                <?php foreach ($log_counts as $count){ ?>
                <option value="<?php echo $count; ?>" <?php echo $log_count == $count ? 'selected' : ''; ?>><?php echo $count; ?></option>
                <?php } ?>
            </select>
            <span class="config-hint">Falcongate entries from /var/log/syslog, newest first.</span>
        </form>
<?php
$data = array("target" => "logs", "log_count" => $log_count);
$result = CallAPI('POST', 'http://127.0.0.1:5000/api/v1.0/falcongate/status', json_encode($data));
if (!$result){
    echo ('<p class="error_message">The log entries could not be loaded. The Falcongate API process may be down, or /var/log/syslog may be missing.</p>');
}else{
    $logs = json_decode($result, true);
    if (!is_array($logs) || count($logs) == 0){
        echo ('<p class="config-hint">There are no log entries to show.</p>');
    }else{
        echo ('<pre class="log-view" tabindex="0">'.esc_html(implode('', $logs)).'</pre>');
    }
}
?>
    </section>
</div>

<script type="text/javascript" src="scripts/system_health.js"></script>

<?php
require 'templates/footer.html';
?>
