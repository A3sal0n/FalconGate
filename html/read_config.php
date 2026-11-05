<?php
ini_set('display_errors', 1); error_reporting(E_ALL);
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
<h1>Configuration</h1>

<script type='text/javascript'>
function torAlert() {
    if (document.getElementById('allow_tor').checked) {
        alert("Are you sure you want to allow Tor in your network? Malware can use Tor to hide its traffic!");
    }
}
</script>

<?php
require_once 'Config/Lite.php';
$config = new Config_Lite('user_config.ini');
$main = $config['main'];

// IPs and domains are stored separately but edited together as one comma-separated list.
$join_list = function ($ips, $domains) {
    return implode(',', array_filter(array((string) $ips, (string) $domains), 'strlen'));
};
$blacklist = $join_list($main['blacklist'], $main['domain_blacklist']);
$whitelist = $join_list($main['whitelist'], $main['domain_whitelist']);
$tor_allowed = $main['allow_tor'] == 'true';
$has_mailer_pwd = (string) $main['mailer_pwd'] !== '';

if (isset($_GET['updated']) && $_GET['updated'] == 'True'){
    echo ('<p class="config-notice" role="status">Configuration saved. Falcongate is restarting to apply it.</p>');
}
?>

<form name="user_config" id="user_config" class="config-page" action="save_config.php" onsubmit="return ValidateInput();" method="post">
    <?php echo csrf_field(); ?>

    <div class="config-columns">
        <section class="config-card">
            <h2>Email alerts</h2>

            <label for="dst_emails">Alert recipients</label>
            <input type="text" id="dst_emails" name="dst_emails" value="<?php echo esc_html($main['dst_emails']); ?>">
            <p class="config-hint">Who receives alert emails. Separate multiple addresses with commas.</p>

            <label for="mailer_address">Gmail address</label>
            <input type="text" id="mailer_address" name="mailer_address" autocomplete="off" value="<?php echo esc_html($main['mailer_address']); ?>">
            <p class="config-hint">The account Falcongate sends alerts from.</p>

            <label for="mailer_pwd">Gmail App Password</label>
            <input type="password" id="mailer_pwd" name="mailer_pwd" maxlength="500" autocomplete="new-password" placeholder="<?php echo $has_mailer_pwd ? 'Saved. Leave blank to keep it.' : 'Not set'; ?>">
            <p class="config-hint">Use an <a href="https://myaccount.google.com/apppasswords" target="_blank" rel="noopener noreferrer">App Password</a>, not your regular account password.</p>
        </section>

        <section class="config-card">
            <h2>Threat intelligence</h2>

            <label for="vt_key">VirusTotal API key</label>
            <input type="text" id="vt_key" name="vt_key" autocomplete="off" value="<?php echo esc_html($main['vt_api_key']); ?>">
            <p class="config-hint">Your personal key, used to look up domains, IP addresses and files.</p>

            <label for="email_watchlist">Email watchlist</label>
            <textarea id="email_watchlist" name="email_watchlist" rows="5"><?php echo esc_html($main['email_watchlist']); ?></textarea>
            <p class="config-hint">Email addresses to check against breaches of third-party online services.</p>
        </section>
    </div>

    <section class="config-card">
        <h2>Blocking rules</h2>

        <div class="config-columns">
            <div>
                <label for="blacklist">Blacklist</label>
                <textarea id="blacklist" name="blacklist" rows="6"><?php echo esc_html($blacklist); ?></textarea>
                <p class="config-hint">IP addresses and domains to block, separated by commas.</p>
            </div>
            <div>
                <label for="whitelist">Whitelist</label>
                <textarea id="whitelist" name="whitelist" rows="6"><?php echo esc_html($whitelist); ?></textarea>
                <p class="config-hint">IP addresses and domains that should never be blocked, separated by commas.</p>
            </div>
        </div>

        <label class="config-check" for="allow_tor">
            <input type="checkbox" id="allow_tor" name="allow_tor" value="1" onchange="torAlert()" <?php echo $tor_allowed ? 'checked' : ''; ?>>
            Allow traffic to the Tor network
        </label>
        <p class="config-hint">Leave this off unless you need it, because malware can use Tor to hide its traffic.</p>
    </section>

    <div class="config-actions">
        <input class="config_button" type="submit" value="Save changes" name="mailer_submit" id="mailer_submit">
        <span class="config-hint">Saving restarts Falcongate.</span>
    </div>
</form>

<?php
require 'templates/footer.html';
?>
