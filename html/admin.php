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

<h1>Administration</h1>

<script type="text/javascript">
function checkPasswordForm() {
    var re = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,72}$/;
    if (!re.test(document.getElementById("pwd").value)) {
        alert("The password you have entered is not enough complex!\n\nThe password must contain lowercase, uppercase, digits and must be between 8 and 72 characters long.");
        return false;
    }
    return true;
}
</script>

<?php
if (isset($_GET['updated']) && $_GET['updated'] == 'True'){
    echo ('<p class="config-notice" role="status">The admin password was changed.</p>');
}
?>

<div class="config-page">
    <div class="config-columns">
        <section class="config-card">
            <h2>Admin password</h2>

            <form name="admin_password" action="admin_actions.php" method="post" onsubmit="return checkPasswordForm();">
                <?php echo csrf_field(); ?>
                <label for="pwd">New password</label>
                <input type="password" id="pwd" name="pwd" maxlength="72" autocomplete="new-password">
                <p class="config-hint">Use 8 to 72 characters, with lowercase letters, uppercase letters and digits.</p>
                <div class="config-actions">
                    <input class="config_button" type="submit" value="Change password" name="update_pwd" id="update_pwd">
                </div>
            </form>
        </section>

        <section class="config-card">
            <h2>Device</h2>

            <form class="admin-action" name="admin_reboot" action="admin_actions.php" method="post" onsubmit="return confirm('Reboot the device now? Network traffic will stop until it has restarted.');">
                <?php echo csrf_field(); ?>
                <div>
                    <h3>Reboot device</h3>
                    <p class="config-hint">Restarts the device. Network traffic stops until it is back up.</p>
                </div>
                <input class="config_button" type="submit" value="Reboot" name="reboot">
            </form>

            <form class="admin-action" name="admin_reset" action="admin_actions.php" method="post" onsubmit="return confirm('Reset Falcongate? This deletes all alerts and settings and restores the default admin password. This cannot be undone.');">
                <?php echo csrf_field(); ?>
                <div>
                    <h3>Reset Falcongate</h3>
                    <p class="config-hint">Deletes all alerts and settings, and restores the default admin password. This cannot be undone.</p>
                </div>
                <input class="config_button config_button_danger" type="submit" value="Reset" name="reset">
            </form>
        </section>
    </div>
</div>

<?php
require 'templates/footer.html';
?>
