<?php
// Included from footer.html. The guard keeps a direct request to this file harmless.
if (!function_exists('is_default_password') || !is_default_password()) {
    return;
}
?>
<dialog id="password_prompt" class="password-prompt" aria-labelledby="password_prompt_title">
	<form id="password_prompt_form" action="set_admin_password.php" method="post">
		<?php echo csrf_field(); ?>
		<h2 id="password_prompt_title">Change the default password</h2>
		<p>This device is still using the default admin password. Choose a new one to continue.</p>
		<label for="new_pwd">New password</label>
		<input type="password" id="new_pwd" name="pwd" maxlength="72" autocomplete="new-password" required autofocus>
		<label for="new_pwd_confirm">Confirm new password</label>
		<input type="password" id="new_pwd_confirm" name="pwd_confirm" maxlength="72" autocomplete="new-password" required>
		<p class="notes">Use 8 to 72 characters, with lowercase letters, uppercase letters and digits.</p>
		<p id="password_prompt_error" class="error_message" role="alert"></p>
		<div class="password-prompt-actions">
			<a href="logout.php">Log out</a>
			<input class="config_button" type="submit" id="password_prompt_submit" value="Change password">
		</div>
	</form>
	<p id="password_prompt_success" class="password-prompt-success" role="status" hidden>Your password was changed successfully.</p>
</dialog>
<script>
(function(){
	var dialog = document.getElementById("password_prompt");
	var form = document.getElementById("password_prompt_form");
	var error = document.getElementById("password_prompt_error");
	var submit = document.getElementById("password_prompt_submit");

	// The password has to be changed, so Esc must not dismiss the window.
	dialog.addEventListener("cancel", function(event){
		event.preventDefault();
	});
	dialog.addEventListener("close", function(){
		dialog.showModal();
	});

	form.addEventListener("submit", function(event){
		event.preventDefault();
		error.textContent = "";
		submit.disabled = true;

		fetch(form.action, {method: "POST", body: new FormData(form), credentials: "same-origin"})
			.then(function(response){
				return response.json();
			})
			.then(function(result){
				if (result.ok) {
					// Leave time to read the confirmation; the reload closes the window.
					form.hidden = true;
					document.getElementById("password_prompt_success").hidden = false;
					setTimeout(function(){
						window.location.reload();
					}, 2500);
				} else {
					error.textContent = result.error;
					submit.disabled = false;
				}
			})
			.catch(function(){
				error.textContent = "The password could not be changed. Reload the page and try again.";
				submit.disabled = false;
			});
	});

	dialog.showModal();
})();
</script>
