function FindProxyForURL(url, host) {
    // SETTINGS
    // your proxy hostname (myproxy.mynetwork.local)
    var proxyHostname = "${asg_hostname}";
    var proxyPort = 8080;

    // regex patterns to exclude from proxy (put your internal networks here)
    var directRegexPatterns = [
        "*.local/*",
        "*.lan/*",
        "*192.168.0.*",
        "*172.16.*",
        "*172.30.0.*"
    ];

    // networks that should use proxies with optional proxy to use override (put your internal networks that should be proxied here)
    var nets = [
        { addr: "172.16.0.0", subnet: "255.255.0.0" },
        { addr: "172.30.0.0", subnet: "255.255.255.0", proxy: "172.30.0.1:" + proxyPort },
        { addr: "192.168.0.0", subnet: "255.255.255.0" }
    ];

    var p = "DIRECT";
    var defaultproxyurl = "PROXY " + proxyHostname + ":" + proxyPort;


    // ACTIONS

    //Don't proxy connections to the proxy web interface
    if (shExpMatch(url, "https://${asg_hostname}*")) { p = "DIRECT"; }
    else if (shExpMatch(url, "https://" + dnsResolve(host) + "*")) { p = "DIRECT"; }
    //Exclude non-fqdn hosts from being proxied
    else if (isPlainHostName(host)) { p = "DIRECT"; }
    else {
        var hasRegexMatch = false;

        // check proxy exclusion regex patterns
        for (var i = 0; i < directRegexPatterns.length; i++) {
            var pattern = directRegexPatterns[i];
            if (shExpMatch(url, pattern)) {
                p = "DIRECT";
                hasRegexMatch = true;
                break;
            }
        }

        if (!hasRegexMatch) {
            // check if client is in proxy network
            var ipstr = "";
            if (typeof myIpAddressEx === "undefined") {
                alert("myIpAddressEx is undefined!"); // this will print to a specific log in the browser
                ipstr = myIpAddress(); // only one ip, not all, but FF does not support the "Ex" version...
            } else {
                ipstr = myIpAddressEx(); // IP1;IP2;IP3
            }

            var ips = ipstr.split(";");
            for (var j = 0; j < nets.length; j++) {
                var net = nets[j];
                for (var i = 0; i < ips.length; i++) {
                    var ip = ips[i];
                    if (isInNet(ip, net.addr, net.subnet)) {
                        var proxyToUse = defaultproxyurl;
                        if(net.proxy){
                            proxyToUse = "PROXY " + net.proxy;
                        }
                        p = proxyToUse;
                        // alert("found " + proxyToUse + " because: " + ip + " is in net " + net.addr + " / " + net.subnet);
                        break;
                    }
                }
            }
        }
    }

    return p;
}