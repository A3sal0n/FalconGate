<?php
session_start();
include_once 'includes/functions.php';
$data = array("target" => "alerts");
$result = CallAPI('POST', 'http://127.0.0.1:5000/api/v1.0/falcongate/status', json_encode($data));
if (!$result){
    echo ("<h3><span class=error_message>Eggshell API process seems to be down!<span></h3>");
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
            $nextrow[0] = date('Y/m/d H:i:s', $alert[2]);
            $nextrow[1] = date('Y/m/d H:i:s', $alert[3]);
            $nextrow[2] = $alert[7];
            $nextrow[3] = $alert[6];
            $nextrow[4] = $alert[8];
            fputcsv($output, $nextrow);
        }
    }
}
?>