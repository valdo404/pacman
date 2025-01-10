// PROXY.PAC by xhark!
var DIRECT = "DIRECT";

// proxies ibvpn
var PROXY_UK = "PROXY uk3.ibvpn.com:9339";
var PROXY_NL = "PROXY nl2.ibvpn.com:9339";

function FindProxyForURL(url, host) {

if (shExpMatch(url, "https://www.youtube.com/watch?v=oSnTfO7b1-M"))
 { return PROXY_UK; }

// sites via proxy
 if( dnsDomainIs(host, "site-web-n1.fr") ||
 dnsDomainIs(host, "site-web-n2.net") ||
 dnsDomainIs(host, "9ans.xyz"))
 { return PROXY_NL; }

if( dnsDomainIs(host, "bbc.co.uk") ||
 dnsDomainIs(host, "espn.go.com") ||
 dnsDomainIs(host, ".channel4.com"))
 { return PROXY_UK; }

// DEFAULT RULE: Reste du trafic
return DIRECT;
}