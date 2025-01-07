function FindProxyForURL(url, host)
{
if (isPlainHostName(host) || dnsDomainIs(host, ".company.com"))
return "DIRECT";
else
return "PROXY myproxy.company.com:8080; DIRECT";
}