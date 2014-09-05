<?php
/*

    HostInfo.PHP, v1.00 - PHP port scanner
    Copyright (c) Kristaps Kaupe 2004. Licensed under BSD license.
    e-mail: neons@hackers.lv
    Web: http://neons.sytes.net

*/

$host = $_GET["host"];
if (empty($host)) { $host = $_SERVER["REMOTE_ADDR"]; }
$ip = gethostbyname($host);

$phpver = phpversion();
if ($phpver < "4.0") { die("At least PHP 4.0 is required!"); }
$safe_mode = ini_get("safe_mode");

if (isset($_GET["st"])) { 
    $st = $_GET["st"];        // TCP connect() scan ?
    if (isset($_GET["st_from"])) {
    $st_from = intval($_GET["st_from"]);
    }
    else {
    $st_from = "0";
    }
    if (isset($_GET["st_to"])) {
    $st_to = intval($_GET["st_to"]);
    }
    else {
    $st_to = "65535";
    }
    if ($st_to < $st_from) { $st_to = $st_from; }
}

if (isset($_GET["si"])) {
    $si = $_GET["si"];        // obtain service-specific info?
}

?>
<html>
<head>
    <title>HostInfo [ <?php echo(htmlspecialchars($host)); ?> ]</title>
    <style><!--
    body { font-family: Arial, sans-serif; color: #000000; background: #FFFFFF; }
    a { color: #0000FF; }
    a:visited { color: #0000FF; }
    a:hover { color: #007FFF; }
    a:active { color: #007FFF; }
    -->
    </style>
</head>
<body bgcolor="#FFFFFF" text="#000000" link="#0000FF" vlink="#0000FF" alink="#007FFF">

<h1>HostInfo</h1>

<p>Copyright &copy; Kristaps Kaupe 2004. <a href="http://neons.sytes.net">neons.sytes.net</a></p>
<hr />

<form method="query">
<?php
    if (isset($si)) {
?>
    <input type="hidden" name="si" value="true" />
<?php
    }
    if (isset($st)) {
?>    
    <input type="hidden" name="st" value="true" />
    <input type="hidden" name="st_from" value="<?= $st_from; ?>" />
    <input type="hidden" name="st_to" value="<?= $st_to; ?>" />
<?php
    }    
?>
    <input type="text" name="host" maxlength="128" value="<?php echo(htmlspecialchars($host)); ?>" />
    <input type="submit" value="Scan" />
<a href="#advanced_form"><small>Advanced options...</small></a>
</form>

<hr />

<?php

error_reporting(E_ALL);
@ob_end_flush();
ob_implicit_flush();
if (!$safe_mode) { set_time_limit(0); }


?>

<p>Requested host: <?php echo htmlspecialchars($host); ?></p>

<h2>Basic info</h2>

<table>
    <tr>
    <td>Hostname:</td>
    <td><?php
    $hostname = @gethostbyaddr($ip);
    if (empty($hostname)) { echo "(unresolved)"; }
    else { echo $hostname; }
    if (strpos($hostname, ".")) {
    $tld = strrev(substr(strrev($hostname), 0, strpos(strrev($hostname), ".")));
    if ((!empty($tld)) && (!is_numeric($tld))) {
        echo " [ <a href=\"http://www.iana.org/root-whois/$tld.htm\" target=\"_blank\">$tld</a> ]";
    }
    }
?>    </td>
    </tr>
    <tr>
    <td>IP:</td>
    <td><?php

echo "$ip ";
if (!empty($hostname)) {
    echo "[ <a href=\"http://www.ripe.net/perl/whois?form_type=simple&full_query_string=&searchtext=$ip&do_search=Search\" target=\"_blank\">ripe</a> ] ";
    echo "[ <a href=\"http://ws.arin.net/cgi-bin/whois.pl?queryinput=$ip\" target=\"_blank\">arin</a> ] ";
    echo "[ lacnic ]";
    echo "[ <a href=\"http://www.apnic.net/apnic-bin/whois.pl?searchtext=$ip\" target=\"_blank\">apnic</a> ] ";
    echo "[ afrinic ]";
}
?>
    </td>
    </tr>
    <tr>
    <td>IP list:</td>
    <td><?php
    $ip_list = gethostbynamel($host);
    foreach ($ip_list as $key => $value) {
    echo "$value<br />";
    }    
?>
    </td>
    </tr>
    <tr>
    <td>DNS records:</td>
    <td><?php
        if (checkdnsrr($host, "A")) { echo "A "; }
        if (checkdnsrr($host, "MX")) { echo "MX "; $dns_mx = true; }
        if (checkdnsrr($host, "NS")) { echo "NS "; }
        if (checkdnsrr($host, "SOA")) { echo "SOA "; }
        if (checkdnsrr($host, "PTR")) { echo "PTR "; }
        if (checkdnsrr($host, "CNAME")) { echo "CNAME "; }
        if ($phpver >= "5.0") {
        if (checkdnsrr($host, "AAAA")) { echo "AAAA "; }
        }
        if (!checkdnsrr($host, "ANY")) { echo "(none)"; }
?>
    </td>
    </tr>
<?php
    if (isset($dns_mx)) {
?>
    <tr>
    <td>MX records:</td>
    <td><?php

    if (getmxrr($host, $mxhosts)) {
    foreach ($mxhosts as $key => $value) { echo "$value<br />"; }
    }
    else {
    echo "(none)";
    }

?>
    </td>
    </tr>
<?php
    }
?>
</table>

<?php

if (strpos($ip, "255") !== false) {
    $broadcast = true;
    echo "<p>NOTE: $ip is a broadcast address.";
    if ((isset($st)) || (isset($uu))) {
    echo " Port scanning is not possible!";
    }
    echo "</p>";
}

if ((!empty($hostname)) && (!isset($broadcast))) {

if ((isset($st)) || (isset($uu))) {
?>
<h2>Port scanning</h2>
<?php
}

$timeout = 30;

$portScanStart = time();

echo "<ul>";
for ($portno = 0; $portno <= 65535; $portno++) {

    // TCP connect() scan
    if ((isset($st)) && ($portno >= $st_from) && ($portno <= $st_to)) {
    $sock = @fsockopen($ip, $portno, $e1, $e2, $timeout);
    if ($sock) {
        echo "   <li>Found open port <b>tcp/$portno</b> (".getservbyport($portno, "tcp").")";

        if (isset($si)) {    
        // More info on specific services
        switch ($portno) {
    
            // HTTP (tries to get server-software)
            case 80:
            $out = "GET / HTTP/1.0\r\n";
            $out .= "Connection: close\r\n\r\n";
            fputs($sock, $out);
            while (!feof($sock)) {
                $data = fgets($sock, 128);
                if (strstr($data, "Server:") !== false) { echo "<br />$data"; }
                elseif (strstr($data, "X-Powered-By:") !== false) { echo "<br />$data"; }
            }
            echo "</li>";
            break;
            
            // FTP, SSH, SMTP, POP3 (outputs everything)
            case 21:
            case 22:
            case 25:
            case 110:
            $data = fgets($sock, 128);
            echo "<br />$data</li>";
            break;
        
            // IRC
            case 6667:
            if (extension_loaded("ircg")) {
                $conn_id = ircg_pconnect("_".substr(uniqid(""), 0, 8), $ip, $portno);
                if ($conn_id) {
                echo "<br />";
                echo "IRC server is running</li>";
                ircg_disconnect($conn_id, "");
                }
                else {
                echo " [irc failed]";
                }
            }
            echo "</li>";
            break;

            default:
            echo "</li>";
        }
        }    
        fclose($sock);
    }
    }
    
}
echo "</ul>";

$portScanEnd = time();
$portScanTime = $portScanEnd - $portScanStart;

if (isset($st)) {
?>
<p>The port scan took about <?php echo($portScanTime); ?> second(s) to scan <?php echo ($st_to - $st_from + 1); ?>
TCP ports.</p>

<?php
}

}

?>

<hr />
<a name="advanced_form"></a>

<form method="query">
    <input type="text" name="host" maxlength="128" value="<?php echo(htmlspecialchars($host)); ?>" />
    <input type="submit" value="Scan" />
    <br />
    <input type="checkbox" name="st" <?php if (isset($st)) { echo "checked=\"checked\""; } ?> /> TCP connect() scan
       from <input type="text" name="st_from" size="5" maxlength="5" value="<?php
    if (isset($st_from)) { echo $st_from; } 
    else { echo "0"; }
       ?>" />
       to <input type="text" name="st_to" size="5" maxlength="5" value="<?php
        if (isset($st_to)) { echo $st_to; }
    else { echo "1024"; }
       ?>" />
    <br />
    <input type="checkbox" name="si" <?php if (isset($si)) { echo "checked=\"checked\""; } ?> /> Obtain service-specific info from ports
</form>

<hr />

</body>
</html>
