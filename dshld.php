<?php
/**
 * @package D-SHLD Anti Flood And DoS/DDoS Module
 * @version 1.0
 */
 error_reporting(0);
 /////////////////////////////////// CONFiG MENU ///////////////////////////////////////////////
 $use_captcha                       = "y"; //If you want to use reCAPTCHA set value to "y" otherwise leave it empty (default is "y").
 $publickey                         = "6Ld6fNESAAAAAIM4YzckCmfqyzFOmrrTj2Qq55Tq"; // Get a key from https://www.google.com/recaptcha/admin/create
 $privatekey                        = "6Ld6fNESAAAAAKWYKMAypEffxoUlpW8RZ5UYGmaK"; // Get a key from https://www.google.com/recaptcha/admin/create
 $interval                          = 0.5; //Connection Interval in seconds (e.g. 1, 0.5, 0.001, etc.).
 $conection_limit                   = 1; //Connection count in the interval value (e.g. 1, 3, 5, 100).
 $block_proxies                     = ""; //If you want to block proxies set value to "y" otherwise leave it empty.
 $refresh_timeout                   = 10; //Suspended Process Timeout value in seconds.
 $redirection                       = ""; //If you want to redirect user after the suspended process, you can enter URL here.
 $mail_info                         = ""; //Mail address to notify (admin mail).
 $debug_info                        = "y"; //If you want to show debug info then set value to "y" otherwise leave it empty.
 $behind_reverse_proxy              = ""; //If your web server behind a reverse proxy, set this value to "y".
 $incremental_blocking              = "y"; //If you want to use incremental blocking, set this value to "y" (default is "y").
 $implicit_deny_timeout             = 0; // (Token access) If you want to block every request as default and let the human users (use_captcha) to view page for a timeout period (seconds), set this value to greater than "0" (default is "0").
 $implicit_deny_for_banlist_timeout = 0; // (Token access) If you want to block every recorded IP that is listed in the banlist as default and let the human users (use_captcha) to view page for a timeout period (seconds), set this value to greater than "0" (default is "0").
 $cached_requests                   = 150; //Monitoring data window size for the last requests (for "ips" file size) (default is "150").
 $use_whitelist                     = ""; //If you want to use whitelist set value to "y" otherwise leave it empty (default is empty).
 $use_excluded                      = ""; //If you want to use excluded file list, set this value to "y" otherwise leave it empty (default is empty).
 ///////////////////////////////////////////////////////////////////////////////////////////
 if (($behind_reverse_proxy == "y") && ($block_proxies == "y")) {
     die("D-SHLD - Your Ip Adress Banned");
 }
 if ($interval >= $refresh_timeout) {
     die("D-SHLD - Sloww Man :) \$ - \$refresh_timeout value.");
 }
 $banlisttemp = 'r00t/banlisttemp';
 $whitelist   = 'r00t/whitelist';
 $excluded    = 'r00t/excluded';
 $ips         = 'r00t/ips';
 $banlist     = 'r00t/banlist';
 define("RECAPTCHA_API_SERVER", "http://www.google.com/recaptcha/api");
 define("RECAPTCHA_API_SECURE_SERVER", "https://www.google.com/recaptcha/api");
 define("RECAPTCHA_VERIFY_SERVER", "www.google.com");
 function _recaptcha_qsencode($data)
 {
     $req = "";
     foreach ($data as $key => $value)
         $req .= $key . '=' . urlencode(stripslashes($value)) . '&';
     $req = substr($req, 0, strlen($req) - 1);
     return $req;
 }
 function _recaptcha_http_post($host, $path, $data, $port = 80)
 {
     $req          = _recaptcha_qsencode($data);
     $http_request = "POST $path HTTP/1.0\r\n";
     $http_request .= "Host: $host\r\n";
     $http_request .= "Content-Type: application/x-www-form-urlencoded;\r\n";
     $http_request .= "Content-Length: " . strlen($req) . "\r\n";
     $http_request .= "User-Agent: reCAPTCHA/PHP\r\n";
     $http_request .= "\r\n";
     $http_request .= $req;
     $response = '';
     if (false == ($fs = @fsockopen($host, $port, $errno, $errstr, 10))) {
         die('Could not open socket');
     }
     fwrite($fs, $http_request);
     while (!feof($fs))
         $response .= fgets($fs, 1160);
     fclose($fs);
     $response = explode("\r\n\r\n", $response, 2);
     return $response;
 }
 function recaptcha_get_html($pubkey, $error = null, $use_ssl = false)
 {
     if ($pubkey == null || $pubkey == '') {
         die("To use reCAPTCHA you must get an API key from <a href='https://www.google.com/recaptcha/admin/create'>https://www.google.com/recaptcha/admin/create</a>");
     }
     if ($use_ssl) {
         $server = RECAPTCHA_API_SECURE_SERVER;
     } else {
         $server = RECAPTCHA_API_SERVER;
     }
     $errorpart = "";
     if ($error) {
         $errorpart = "&amp;error=" . $error;
     }
     return '<script type="text/javascript" src="' . $server . '/challenge?k=' . $pubkey . $errorpart . '"></script>

    <noscript>
          <iframe src="' . $server . '/noscript?k=' . $pubkey . $errorpart . '" height="300" width="500" frameborder="0"></iframe><br/>
          <textarea name="recaptcha_challenge_field" rows="3" cols="40"></textarea>
          <input type="hidden" name="recaptcha_response_field" value="manual_challenge"/>
    </noscript>';
 }
 class ReCaptchaResponse
 {
     var $is_valid;
     var $error;
 }
 function recaptcha_check_answer($privkey, $remoteip, $challenge, $response, $extra_params = array())
 {
     if ($privkey == null || $privkey == '') {
         die("To use reCAPTCHA you must get an API key from <a href='https://www.google.com/recaptcha/admin/create'>https://www.google.com/recaptcha/admin/create</a>");
     }
     if ($remoteip == null || $remoteip == '') {
         die("For security reasons, you must pass the remote ip to reCAPTCHA");
     }
     if ($challenge == null || strlen($challenge) == 0 || $response == null || strlen($response) == 0) {
         $recaptcha_response           = new ReCaptchaResponse();
         $recaptcha_response->is_valid = false;
         $recaptcha_response->error    = 'incorrect-captcha-sol';
         return $recaptcha_response;
     }
     $response           = _recaptcha_http_post(RECAPTCHA_VERIFY_SERVER, "/recaptcha/api/verify", array(
         'privatekey' => $privkey,
         'remoteip' => $remoteip,
         'challenge' => $challenge,
         'response' => $response
     ) + $extra_params);
     $answers            = explode("\n", $response[1]);
     $recaptcha_response = new ReCaptchaResponse();
     if (trim($answers[0]) == 'true') {
         $recaptcha_response->is_valid = true;
     } else {
         $recaptcha_response->is_valid = false;
         $recaptcha_response->error    = $answers[1];
     }
     return $recaptcha_response;
 }
 function recaptcha_get_signup_url($domain = null, $appname = null)
 {
     return "https://www.google.com/recaptcha/admin/create?" . _recaptcha_qsencode(array(
         'domains' => $domain,
         'app' => $appname
     ));
 }
 function _recaptcha_aes_pad($val)
 {
     $block_size = 16;
     $numpad     = $block_size - (strlen($val) % $block_size);
     return str_pad($val, strlen($val) + $numpad, chr($numpad));
 }
 $resp  = null;
 $error = null;
 if (($behind_reverse_proxy == "y") && ($block_proxies <> "y")) {
     $REMOTE_ADDR = $_SERVER['HTTP_X_FORWARDED_FOR'];
 } else {
     $REMOTE_ADDR = $_SERVER['REMOTE_ADDR'];
 }
 function isValidIP($ip)
 {
     $pattern = "/^([1]?\d{1,2}|2[0-4]{1}\d{1}|25[0-5]{1})(\.([1]?\d{1,2}|2[0-4]{1}\d{1}|25[0-5]{1})){3}$/";
     return (preg_match($pattern, $ip) > 0) ? true : false;
 }
 if (isValidIP($_SERVER['HTTP_VIA'])) {
     $HTTP_VIA = $_SERVER['HTTP_VIA'];
 } else {
     $HTTP_VIA = "";
 }
 if (isValidIP($_SERVER['HTTP_X_FORWARDED_FOR'])) {
     $HTTP_X_FORWARDED_FOR = $_SERVER['HTTP_X_FORWARDED_FOR'];
 } else {
     $HTTP_X_FORWARDED_FOR = "";
 }
 $let_it_go = 0;
 

 if (!fopen($banlist, 'r')) {
     fopen($banlist, 'a');
     fclose($banlist);
 }
 
 if ($use_excluded == "y") {
 if (!fopen($excluded, 'r')) {
     fopen($excluded, 'a');
     fclose($excluded);
 }
 $read_excluded  = implode('\n', file($excluded));
 if (eregi($_SERVER['PHP_SELF'], $read_excluded)) {
     $let_it_go = 1;
 }
 }
 
 $read_blacklist = implode('\n', file($banlist));
 
 if ($use_whitelist == "y") {
 if (!fopen($whitelist, 'r')) {
     fopen($whitelist, 'a');
     fclose($whitelist);
 }
 $read_whitelist = implode('\n', file($whitelist));
 if (eregi($REMOTE_ADDR, $read_whitelist)) {
     $let_it_go = 1;
 }
 }


 if ($let_it_go == 0) {
     if (eregi($REMOTE_ADDR, $read_blacklist) && ($implicit_deny_for_banlist_timeout > 0)) {
         $implicit_deny_timeout = $implicit_deny_for_banlist_timeout;
     }
	  if (!isset($_SESSION) && $implicit_deny_timeout > 0) {
         session_start();
     }
	 if ($implicit_deny_for_banlist_timeout == 0 or ($implicit_deny_for_banlist_timeout > 0 and $_SESSION['unblocked_time'] > time())) {
	 
     $linesx = file($banlisttemp);
     foreach ($linesx as $teksira) {
         $ipcheck = explode('|', $teksira);
     }
     $connection_count = 1;
     $saniye           = (time() + microtime());
     $adres            = $REMOTE_ADDR;
     $dosya            = $ips;
     $dosya_ac         = fopen($dosya, 'r');
     $oku              = fgets($dosya_ac, ($cached_requests * 30));
     fclose($dosya_ac);
     $sira         = explode(">", $oku);
     $array        = $sira[0] + 1;
     $array_gokhan = explode(";", $sira[1]);
     for ($i = 0; $i < $cached_requests; $i++) {
         $ayikla = explode("|", $array_gokhan[$i]);
         if ($HTTP_VIA > "") {
             $kaynak = $HTTP_X_FORWARDED_FOR;
         } else {
             $kaynak = $REMOTE_ADDR;
         }
         if (($kaynak == $ayikla[0] and (time() + microtime()) < $ayikla[2] + $interval) or (($ipcheck[0] == $adres) && ($ipcheck[1] + $refresh_timeout + 0.0 >= (time() + microtime())))) {
             $array_gokhan[$i] = "$adres|" . $connection_count++ . "|$saniye";
             if ($connection_count > $conection_limit) {
?>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-9" />

<meta http-equiv="Content-Language" content="tr">
<meta http-equiv="Refresh" content="<?php
                 echo $refresh_timeout;
?>; url=<?php
                 echo $redirection;
?>">
<title>D-SHLD Anti Flood And DoS/DDoS Module</title>
</head>


<body topmargin="0" leftmargin="0" rightmargin="0" bottommargin="0" marginwidth="0" marginheight="0" bgcolor="#C0C0C0">
<script>
var count=<?php
                 echo $refresh_timeout;
?>;

var counter=setInterval("timer()",1000); 

function timer()
{
  count=count-1;
  if (count <= 0)
  {
     clearInterval(counter);
     return;
  }

 document.getElementById("timer").innerHTML=count + " ";

}
</script>
<p>
&nbsp;</p>
<table border="0" style="border-collapse: collapse" width="100%" cellpadding="0" height="110">
<tr>
                <td bgcolor="BLACK">
                <div align="center">
                    <p>
                    <br>
                    <img border="0" src="logo.png" ></p>
                    <table border="0" width="336" id="table1" cellspacing="1"  height="66">
                        <tr>
                            <td valign="top" style="border-style: double; border-width: 3px; padding-left: 4px; padding-right: 4px; padding-top: 1px; padding-bottom: 1px">
                            <p align="center">
                            <font face="Verdana" style="font-size: 9pt; font-weight: 700"  color="#00FF90">
                            <br>
                            D-SHLD Anti Flood And DoS/DDoS Module<br>
                            </font>
                            <font face="Verdana" style="font-size: 9pt; font-weight: 700"  color="#C9C0C0">
                            <br>
                            </font>
                        
                            <font face="Arial" style="font-size: 8pt" color="#C0C0C0">
                            <b>Your Process Interrupted by Module<br>Your IP Address has been Logged</b><br>
                    ~ Please Wait <b><span id="timer"></span></b> Second(s) ~<br> &nbsp;</font></td>
                    </tr>
                </table>
                    </div>
                <p>
<br>
<font face="Arial" style="font-size: 8pt" color="#33ff00"><?php
                 echo base64_decode("Q29weXJpZ2h0IEdpdEh1Yi5Db20vQjBSVTcwL0QtU0hMRCAyMDE4IC0gRXJ0dWdydWwgQWTDvGd1emVs");
                 echo base64_decode("PGJvZHkgYmFja2dyb3VuZD0iaHR0cHM6Ly93d3cuc2V0YXN3YWxsLmNvbS93cC1jb250ZW50L3VwbG9hZHMvMjAxNy8wMy9Ccmljay1Ccmlja3MtUGF0dGVybi1XYWxscGFwZXItMTkyMHgxMDgwLmpwZyI+PC9ib2R5Pg==");
?></font>
</table>
<p>&nbsp;</p>

<?php
                 for ($e = 0; $e < $cached_requests; $e++) {
                     $veri_handler = "$veri_handler;$array_gokhan[$e]";
                 }
                 $g_muharremoglu = fopen($dosya, 'w');
                 $veri_handler   = "$sira[0]>$veri_handler";
                 fputs($g_muharremoglu, "$veri_handler");
                 fclose($g_muharremoglu);
                 if (($ipcheck[0] == $adres) && ($ipcheck[1] + $refresh_timeout >= (time() + microtime()))) {
                     $logfile = $banlist;
                     $read    = implode('\n', file($logfile));
                     if (eregi($adres, $read)) {
                     } else {
                         $htaccess2 = fopen($banlist, 'a');
                         fwrite($htaccess2, $adres . "\n");
                         fclose($htaccess2);
                         if ($mail_yolla <> "") {
                             mail($mail_yolla, "$adres", "http://" . $_SERVER['HTTP_HOST'] . "/" . $_SERVER['PATH_INFO'] . $banlist, "From: IOSEC Anti Flood <iosec@" . $_SERVER['HTTP_HOST'] . ">\r\n");
                         }
                     }
                 } else {
                     $htaccess = fopen($banlisttemp, 'a+');
                     if (filesize($banlisttemp) > ($cached_requests * 30)) {
                         fopen($banlisttemp, 'w');
                     }
                     fwrite($htaccess, $adres . "|" . (time() + microtime()) . "\n");
                     fclose($htaccess);
                 }
                 $hatali = 1;
                 if ($use_captcha == "y") {
?>

<html>
  <center><body>
    <form action="" method="post">
<?php
                     if ($_POST["recaptcha_response_field"]) {
                         $resp = recaptcha_check_answer($privatekey, $_SERVER["REMOTE_ADDR"], $_POST["recaptcha_challenge_field"], $_POST["recaptcha_response_field"]);
                         if ($resp->is_valid) {
                             $hatali   = 0;
                             $htaccess = fopen($banlisttemp, 'a+');
                             fwrite($htaccess, $adres . "|" . (time() + microtime() - $refresh_timeout) . "\n");
                             fclose($htaccess);
                             echo "<meta http-equiv=\"Refresh\" content=\"" . ($interval + 1) . "; url=\">";
                             exit;
                         } else {
                             $error = $resp->error;
                         }
                     }
                     echo recaptcha_get_html($publickey, $error);
?>
 <br/>
    <input type="submit" value="Unblock" />
    </form>
  </body></center>
</html>
<?php
                 }
                 if (($error <> null) || ($hatali == 1)) {
                     if ($debug_info == "y") {
                         echo "Debug Info<br>";
                         echo "Your IP Address: " . $REMOTE_ADDR . "<br>";
                         echo "Microtime: " . (time() + microtime());
                     }
                     if ($incremental_blocking == "y") {
                         $htaccess = fopen($banlisttemp, 'a+');
                         if (filesize($banlisttemp) > ($cached_requests * 30)) {
                             fopen($banlisttemp, 'w');
                         }
                         fwrite($htaccess, $adres . "|" . (time() + microtime()) . "\n");
                         fclose($htaccess);
                     }
                     exit;
                 }
             }
         }
     }
     $array_gokhan[$array] = "$adres|$connection_count|$saniye";
     for ($e = 1; $e < $cached_requests; $e++) {
         $veri_handler = "$veri_handler;$array_gokhan[$e]";
     }
     if ($array > $cached_requests) {
         $array = 1;
     }
     $write_it       = "$array>$veri_handler";
     $g_muharremoglu = fopen($dosya, 'w');
     fputs($g_muharremoglu, $write_it);
     fclose($g_muharremoglu);
    }
     if (($block_proxies == "y" and $HTTP_VIA > "") or ($implicit_deny_timeout > 0 and $_SESSION['unblocked_time'] < time())) {
?>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-9" />
<title>D-SHLD Anti Flood And DoS/DDoS Module</title>
<body topmargin="0" leftmargin="0" rightmargin="0" bottommargin="0" marginwidth="0" marginheight="0" bgcolor="#E0E0E0">
<p><br>
<br>
<br>
<br>
&nbsp;</p>
<table border="0" style="border-collapse: collapse" width="100%" cellpadding="0" height="110">
<tr>
                <td bgcolor="BLACK">
                <div align="center">
                                        <table border="0" width="336" id="table1" cellspacing="0" cellpadding="0" height="66">
                                                <tr>
                                                        <td valign="center">
                                                        <p align="center">
                                                        <font face="Verdana" style="font-size: 9pt; font-weight: 700" color="#00FF00">
                                                        D-SHLD Anti Flood And DoS/DDoS Module<br>
                                                        </font>
                                                       <font face="Arial" style="font-size: 8pt; " color="#C0C0C0">
                                                        Proxy Usage Prohibited (Implicit Deny Mode)</font></td>
                                                </tr>
                                        </table>
                                </div>

<?php
         if ($use_captcha == "y") {
?>

<html>
  <center><body>
    <form action="" method="post">
<?php
             if ($_POST["recaptcha_response_field"]) {
                 $resp = recaptcha_check_answer($privatekey, $_SERVER["REMOTE_ADDR"], $_POST["recaptcha_challenge_field"], $_POST["recaptcha_response_field"]);
                 if ($resp->is_valid) {
                     $_SESSION['unblocked_time'] = time() + $implicit_deny_timeout;
                     echo "<meta http-equiv=\"Refresh\" content=\"" . ($interval + 1) . "; url=\">";
                     exit;
                 } else {
                     $error = $resp->error;
                 }
             }
             echo recaptcha_get_html($publickey, $error);
?>
 <br/>
    <input type="submit" value="Unblock" />
    </form>
  </body></center>
</html>
<?php
         }
         exit;
     }
 }
?>