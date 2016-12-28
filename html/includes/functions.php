<?php


function login($uname, $password) {

    $lines = file('../pwd.db');
    $string = trim(preg_replace('/\s\s+/', ' ', $lines[0]));
    $fields = preg_split('/\s+/', $string);

    if (($uname == $fields[0]) && (password_verify ($password, $fields[1]) == true)){
        //Get the current IP of the user
        $user_ip = $_SERVER['REMOTE_ADDR'];

        // Get the current user-agent string of the user
        $user_browser = $_SERVER['HTTP_USER_AGENT'];
        $_SESSION['ID'] = hash('sha512', $user_ip . $user_browser);

        return true;
    }else{
        return false;
    }
}

//Check if I really need this one. Probably will have to rewrite some parts
function login_check() {
    //Get the current IP of the user
    $user_ip = $_SERVER['REMOTE_ADDR'];

    // Get the current user-agent string of the user.
    $user_browser = $_SERVER['HTTP_USER_AGENT'];

    $login_check = hash('sha512', $user_ip . $user_browser);
    if ($_SESSION){
        if ($_SESSION['ID'] == $login_check){
            // Logged In!!!!
            return true;
        }else {
            // Not logged in
            return false;
        }
    }else{
        // Not logged in
        return false;
    }
}


function esc_url($url) {

    if ('' == $url) {
        return $url;
    }

    $url = preg_replace('|[^a-z0-9-~+_.?#=!&;,/:%@$\|*\'()\\x80-\\xff]|i', '', $url);

    $strip = array('%0d', '%0a', '%0D', '%0A');
    $url = (string) $url;

    $count = 1;
    while ($count) {
        $url = str_replace($strip, '', $url, $count);
    }

    $url = str_replace(';//', '://', $url);

    $url = htmlentities($url);

    $url = str_replace('&amp;', '&#038;', $url);
    $url = str_replace("'", '&#039;', $url);

    if ($url[0] !== '/') {
        // We're only interested in relative links from $_SERVER['PHP_SELF']
        return '';
    } else {
        return $url;
    }
}

function CallAPI($method, $url, $data = false)
{
    $curl = curl_init();
    curl_setopt($curl, CURLOPT_HEADER, false);
    curl_setopt($curl, CURLOPT_HTTPHEADER,array("Content-type: application/json"));

    switch ($method)
    {
        case "POST":
            curl_setopt($curl, CURLOPT_POST, true);

            if ($data)
                curl_setopt($curl, CURLOPT_POSTFIELDS, $data);
            break;
        case "PUT":
            curl_setopt($curl, CURLOPT_PUT, true);
            break;
        default:
            if ($data)
                $url = sprintf("%s?%s", $url, http_build_query($data));
    }

    // Optional Authentication:
    //curl_setopt($curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
    //curl_setopt($curl, CURLOPT_USERPWD, "username:password");

    curl_setopt($curl, CURLOPT_URL, $url);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);

    $result = curl_exec($curl);

    curl_close($curl);

    return $result;
}

function redirect($url)
{
    $string = '<script type="text/javascript">';
    $string .= 'window.location = "' . $url . '"';
    $string .= '</script>';

    echo $string;
}

?>