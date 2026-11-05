<?php
session_start();
include_once 'includes/functions.php';

if (login_check() != true){
    http_response_code(403);
    echo ("<p><span class=error_message>You are not authorized to access this page. Please </span><a href=index.php>login</a>.</p>");
    exit(0);
}

$period = (!isset($_GET['period'])) ? 'alerts_week': $_GET['period'];
$filter = (!isset($_GET['filter'])) ? 'all': $_GET['filter'];
$data = array("target" => "alerts", "timeframe" => $period, "filter" => $filter);
$result = CallAPI('POST', 'http://127.0.0.1:5000/api/v1.0/falcongate/status', json_encode($data));
if (!$result){
    echo ("<h3><span class=error_message>Falcongate API process seems to be down!<span></h3>");
    echo ("<h3><span class=error_message>Check your device's configuration and reboot if necessary.</span></h3>");
}else{
    // Based on code from Stephen Morley
    // http://code.stephenmorley.org/php/creating-downloadable-csv-files/
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename=recent_alerts_'.date('Y-m-d').'.csv');
    // create a file pointer connected to the output stream
    $output = fopen('php://output', 'w');
    
    // output the column headings
    fputcsv($output, array('First seen', 'Last seen', 'Host', 'Threat', 'Indicators'));
    
    $obj = json_decode($result, true);
    
    // fetch the data
    if ($obj[0] != 'none'){
        foreach ($obj as $alert){
            $nextrow = array();
            // Timestamps can be fractional, which date() no longer converts silently.
            $nextrow[0] = date('Y/m/d H:i:s', (int) $alert[2]);
            $nextrow[1] = date('Y/m/d H:i:s', (int) $alert[3]);
            $nextrow[2] = $alert[7];
            $nextrow[3] = $alert[6];
            $nextrow[4] = $alert[8];
            fputcsv($output, $nextrow);
        }
    }
}
?>