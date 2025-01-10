function FindProxyForURL(url, host)

{ if (isInNet(host, "10.0.1.0", "255.255.255.0")) {

return "DIRECT"; }

else if (url.substring(0, 5) == "http:") {

return "PROXY 10.0.1.1:3128"; }

else if (url.substring(0, 6) == "https:") {

return "PROXY 10.0.1.1:3128"; }

else { return "DIRECT"; }

}