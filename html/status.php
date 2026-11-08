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

<h1>Status</h1>

<?php
// The API sends missing values as the text "None", and dnsmasq uses "*" for an unknown hostname.
$known = function ($value) {
    $value = (string) $value;
    return ($value === '' || $value === 'None' || $value === '*') ? 'Unknown' : $value;
};

$status_url = 'http://127.0.0.1:5000/api/v1.0/falcongate/status';
$network = json_decode((string) CallAPI('POST', $status_url, json_encode(array("target" => "network"))), true);

if (!is_array($network) || !isset($network['ip'])){
    echo ('<p class="error_message">The status could not be loaded. The Falcongate API process may be down. Check your device\'s configuration and reboot if necessary.</p>');
}else{
    $devices = json_decode((string) CallAPI('POST', $status_url, json_encode(array("target" => "devices"))), true);
    $settings = array(
        'Interface' => $network['interface'],
        'MAC address' => strtoupper((string) $network['mac']),
        'IP address' => $network['ip'],
        'Default gateway' => $network['gateway'],
        'Network mask' => $network['netmask'],
    );
?>

<div class="config-page">
    <section class="config-card">
        <h2>Network configuration</h2>
        <div class="status-settings">
            <?php foreach ($settings as $label => $value){ ?>
            <div class="status-setting">
                <span class="config-hint"><?php echo $label; ?></span>
                <strong><?php echo esc_html($known($value)); ?></strong>
            </div>
            <?php } ?>
        </div>
    </section>

    <section class="config-card">
        <h2>Active devices</h2>
<?php if (!is_array($devices)){ ?>
        <p class="error_message">The device list could not be loaded.</p>
<?php }elseif (count($devices) == 0){ ?>
        <p class="config-hint">No devices have been detected yet.</p>
<?php }else{ ?>
        <p class="config-hint"><?php echo count($devices); ?> <?php echo count($devices) == 1 ? 'device' : 'devices'; ?>. Select a row to see open ports.</p>
        <table class="alerts-table" id="devices_table">
            <thead>
                <tr>
                    <th>Hostname</th>
                    <th>MAC address</th>
                    <th>IP address</th>
                    <th>Vendor</th>
                    <th><span class="visually-hidden">Details</span></th>
                </tr>
            </thead>
            <tbody>
            <?php
            foreach ($devices as $index => $device){
                $is_appliance = $device['ip'] == $network['ip'];
                $hostname = $is_appliance ? 'Falcongate' : $known($device['hostname']);
                $mac = strtoupper($known($device['mac']));
                $vendor = $is_appliance ? 'Falcongate' : $known($device['vendor']);
                $ports = array();
                foreach ($device['tcp_ports'] as $port){
                    $ports[] = 'TCP/' . (int) $port;
                }
                foreach ($device['udp_ports'] as $port){
                    $ports[] = 'UDP/' . (int) $port;
                }
            ?>
                <tr class="alert-row">
                    <td data-label="Hostname" class="status-hostname"><?php echo esc_html($hostname); ?></td>
                    <td data-label="MAC address"><?php echo esc_html($mac); ?></td>
                    <td data-label="IP address"><?php echo esc_html($device['ip']); ?></td>
                    <td data-label="Vendor"><?php echo esc_html($vendor); ?></td>
                    <td class="alert-toggle"><button type="button" class="alert-details-button" aria-expanded="false" aria-controls="device_details_<?php echo (int) $index; ?>">Details</button></td>
                </tr>
                <tr class="alert-details" id="device_details_<?php echo (int) $index; ?>" hidden>
                    <td colspan="5">
                        <dl>
                            <dt>Hostname</dt><dd><?php echo esc_html($hostname); ?></dd>
                            <dt>MAC address</dt><dd><?php echo esc_html($mac); ?></dd>
                            <dt>IP address</dt><dd><?php echo esc_html($device['ip']); ?></dd>
                            <dt>Vendor</dt><dd><?php echo esc_html($vendor); ?></dd>
                            <dt>Open ports</dt><dd><?php echo count($ports) > 0 ? implode(', ', $ports) : 'None detected'; ?></dd>
                        </dl>
                    </td>
                </tr>
            <?php } ?>
            </tbody>
        </table>

        <script>
        document.getElementById("devices_table").addEventListener("click", function(event){
            var row = event.target.closest(".alert-row");
            if (!row) {
                return;
            }
            var button = row.querySelector(".alert-details-button");
            var details = document.getElementById(button.getAttribute("aria-controls"));
            details.hidden = !details.hidden;
            button.setAttribute("aria-expanded", String(!details.hidden));
            button.textContent = details.hidden ? "Details" : "Hide";
        });
        </script>
<?php } ?>
    </section>
</div>

<?php
}
?>

<?php
require 'templates/footer.html';
?>
