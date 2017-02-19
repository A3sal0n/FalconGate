<style type="text/css">
/* ---------- GENERAL ---------- */
* {
  box-sizing: border-box;
}
*:before, *:after {
  box-sizing: border-box;
}

body {
  background: #eaeaea;
  color: #999;
  font: 400 16px/1.5em sans-serif;
  margin: 0;
}

h3 {
  margin: 0;
}

a {
  color: #999;
  text-decoration: none;
}

a:hover {
  color: #1dabb8;
}

fieldset {
  border: none;
  margin: 0;
}

input {
  border: none;
  font-family: inherit;
  font-size: inherit;
  margin: 0;
  -webkit-appearance: none;
}

input:focus {
  outline: none;
}

input[type="submit"] {
  cursor: pointer;
}

.error_message {
  color: #b30422;

    &:before,
    &:after {
        content: ' ';
        display: table;
    }

}

.logon_status {
    color: #b2b2b2;
    font-size: 9px;
	text-align: center;
	padding-top: 2px;
}



/* ---------- LOGIN-FORM ---------- */
#login-form {
  width: 300px;
}

#login-form h3 {
  background-color: #282830;
  border-radius: 5px 5px 0 0;
  color: #fff;
  font-size: 14px;
  padding: 20px;
  text-align: center;
  text-transform: uppercase;
}

#login-form fieldset {
  background: #fff;
  border-radius: 0 0 5px 5px;
  padding: 20px;
  position: relative;
}

#login-form fieldset:before {
  background-color: #fff;
  content: "";
  height: 8px;
  left: 50%;
  margin: -4px 0 0 -4px;
  position: absolute;
  top: 0;
  -webkit-transform: rotate(45deg);
  transform: rotate(45deg);
  width: 8px;
}

#login-form input {
  font-size: 14px;
}

#login-form input[type="uname"],
#login-form input[type="password"] {
  border: 1px solid #dcdcdc;
  padding: 12px 10px;
  width: 100%;
}

#login-form input[type="uname"] {
  border-radius: 3px 3px 0 0;
}

#login-form input[type="password"] {
  border-top: none;
  border-radius: 0px 0px 3px 3px;
}

#login-form input[type="submit"] {
  background: #1dabb8;
  border-radius: 3px;
  color: #fff;
  float: right;
  font-weight: bold;
  margin-top: 20px;
  padding: 12px 20px;
}

#login-form input[type="submit"]:hover {
  background: #198d98;
}

#login-form footer {
  font-size: 12px;
  margin-top: 16px;
}

.info {
  background: #e5e5e5;
  border-radius: 50%;
  display: inline-block;
  height: 20px;
  line-height: 20px;
  margin: 0 10px 0 0;
  text-align: center;
  width: 20px;
}
</style>
<?php
session_start();

include_once 'includes/functions.php';

if (login_check() == true) {
    $logged = 'in';
} else {
    $logged = 'out';
}
?>
<table height="100%" width="100%">
	<tr>
		<td align="center" valign="center">
        <!-- start login-form-->
        <div class="container">
            <div id="login-form">
            <!-- <img src="images/logo.png" width="250"> -->
            <h3>Login</h3>
            <fieldset>
                <form action="includes/process_login.php" method="post" name="login_form">
                    <input type="uname" name="uname" value="Username">
                    <input type="password" name="passwd" value="Password">
                    <input type="submit" value="Login">
                    <footer class="error_message">
                           <?php
                            if (isset($_GET['error'])) {
                                echo 'Error Logging In!';
                            }
                            ?> 
                    </footer>
                </form>        
            </fieldset>
            </div> <!-- end login-form -->
            <div class="logon_status">
                <?php
                if (login_check() == true) {
                    echo '[Currently logged ' . $logged . '.]';
                } else {
                    echo '[Currently logged ' . $logged . '.]';
                }
                ?>

            </div>
        </div>    
		</td>
	</tr>
</table>	