function FindProxyForURL(url, host) {
// If URL has no dots in host name, send traffic direct.
    if (isPlainHostName(host)) return "DIRECT";
// If specific URL needs to bypass proxy, send traffic direct.
    if (shExpMatch(url,"*bluecoat.com*") ||
     shExpMatch(url,"*cacheflow.com*"))
     return "DIRECT";
// If IP address is internal send direct.
     if (isInNet(host, "10.0.0.0", "255.0.0.0") ||
         isInNet(host, "172.16.0.0", "255.240.0.0") ||
         isInNet(host, "192.168.0.0", "255.255.0.0") ||
         isInNet(host, "216.52.23.0", "255.255.255.0") ||
         isInNet(host, "127.0.0.0", "255.255.255.0") ||
         isInNet(host, "192.41.79.240", "255.255.255.255"))
   return "DIRECT";
// All other traffic uses below proxies, in fail-over order.
      return "PROXY proxy.threatpulse.net:8080; DIRECT";
      return "PROXY 199.19.250.164:8080; DIRECT";
}