<?php
# Config
DEFINE("whiteListIPs", [
    '118.69.225.16', # VPN Server WFH
    '14.161.46.247', # Cuong.phan1 IP
]);
DEFINE("whiteListcountries", ['VN']);
DEFINE("timesAuthenticationFailed", 30);

function addWhiteListIPs($IPs)
{
    foreach ($IPs as $IP) {
        actionFireWall($IP, 'ACCEPT');
    }
}


function detectIPCountry($IP)
{
    $result = exec("whois $IP | grep  country | tail -n 1 | awk '{print $2}'");
    return  strtoupper($result);
}

function isCountryInWhiteList($IP)
{
    return in_array(detectIPCountry($IP), constant("whiteListcountries"));
}

function detectFirewallRuleExist($IP, $ACTION)
{
    # Kiểm tra xem IP này đã ACCEPT hoặc DROP chưa?
    return exec("sudo iptables -L -v -n | grep $IP | grep $ACTION | wc -l");
    # return 0 when failed condition
    # return 1 when true condition
}

function actionFireWall($IP, $ACTION)
{
    $whiteListIPs = constant("whiteListIPs");
    # Thêm rule vào trong firewall
    if($ACTION == "ACCEPT" && detectFirewallRuleExist($IP, $ACTION) == 0)
    {
        # Đối với DROP thì "-I" INSERT
        #echo "sudo iptables -I INPUT -s $IP -j $ACTION\n";
        exec("sudo iptables -I INPUT -s $IP -j $ACTION");
    }
    elseif($ACTION == "DROP" && detectFirewallRuleExist($IP, $ACTION) == 0)
    # Đối với DROP thì "-A" APPEND
        if(isCountryInWhiteList($IP) == TRUE)
            alertTelegram("Detected [$IP] at [".detectIPCountry($IP)."] is brute force attack! But in [WHITELIST] country!");
        else
        {
            # Đối với DROP thì "-A" APPEND
            #echo "sudo iptables -A INPUT -s $IP -j $ACTION\n";
            exec("sudo iptables -A INPUT -s $IP -j $ACTION");
            alertTelegram("Detected [$IP] at [".detectIPCountry($IP)."] is brute force attack! [BANNED] already!!!");

        }
    else
    {
        echo "Done already: sudo iptables -I INPUT -s $IP -j $ACTION\n";
    }
}

function pullingLogZimbra($hostname = '172.16.19.100', $user = 'cuong.phan1', $path = '/var/log/zimbra.log', $save='/tmp/zimbra.log')
{
    exec("scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null $user@$hostname:$path $save");
}

function analyticZimraLogBruteForce($path = '/tmp/zimbra.log')
{
    $tempFile = exec('mktemp analytic.temp.XXXXXXXXX');
    $solan = timesAuthenticationFailed;
    $command = exec('zcat -f /tmp/zimbra.log | grep \'SASL LOGIN authentication failed: authentication failure\' | awk \'{print $7}\' | sort  -nr| uniq -c  | awk \'{if($1 > '.$solan.')print $2 " "  $1}\' | tr -d \':][:alpha:]\'| sort -k2 --numeric-sort | sed \'s/[^.].*\[//\' | sed \'s/\[//\' | tr -d \']\' > ' . $tempFile);
    $data = file_get_contents($tempFile);
    unlink($tempFile);
    $lines = array_filter(explode(PHP_EOL, $data));
    foreach ($lines as $line) {
        $target = explode(' ',$line);
        actionFireWall($target[0],'DROP');
    }

}

function alertTelegram($content)
{
    echo $content;
    // curl -X POST -H 'Content-Type: application/json' -d '{"chat_id": "879804831", "text": "This is a test from curl", "disable_notification": true}' 
    $url = 'https://api.telegram.org/bot1955054417:AAHEzQP2ioNVRodyfgp2llos3abp6I6ajjw/sendMessage';
    $sendToUser = 879804831;
    $ch = curl_init( $url );
    # Setup request to send json via POST.
    $payload = json_encode( array( 'chat_id'=> $sendToUser, 'text'=> $content, 'disable_notification'=> true));
    curl_setopt( $ch, CURLOPT_POSTFIELDS, $payload );
    curl_setopt( $ch, CURLOPT_HTTPHEADER, array('Content-Type:application/json'));
    # Return response instead of printing.
    curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );
    # Send request.
    $result = curl_exec($ch);
    curl_close($ch);
    # Print response.
}

# Make sure the whitelist always adding first.
addWhiteListIPs(whiteListIPs);
# Pulling log file for analytic process
pullingLogZimbra();
# Rule for DROP request!
analyticZimraLogBruteForce();

?>
