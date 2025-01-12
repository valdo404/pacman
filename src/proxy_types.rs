use crate::logic::ToJs;

#[derive(Debug, Clone, PartialEq)]
pub enum ProxyType {
    Direct,
    Http { host: String, port: u16 },
    Https { host: String, port: u16 },
    Socks4 { host: String, port: u16 },
    Socks5 { host: String, port: u16 },
    Socks { host: String, port: u16 },
    Generic { host: String, port: u16 },
    Chain(Vec<ProxyType>),  // Compound proxy chain
}

impl ToJs for ProxyType {
    fn to_js(&self) -> String {
        self.to_string()
    }
}

impl ProxyType {
    pub fn from_str(proxy_str: &str) -> Option<Self> {
        if proxy_str.contains(';') {
            return Some(ProxyType::Chain(
                proxy_str
                    .split(';')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .filter_map(ProxyType::from_single_str)
                    .collect()
            ));
        }
        ProxyType::from_single_str(proxy_str)
    }

    fn from_single_str(proxy_str: &str) -> Option<Self> {
        let parts: Vec<&str> = proxy_str.trim().split_whitespace().collect();
        if parts.len() != 2 {
            return None;
        }

        let proxy_type = parts[0];
        let addr_parts: Vec<&str> = parts[1].split(':').collect();
        if addr_parts.len() != 2 {
            return None;
        }

        let host = addr_parts[0].to_string();
        let port = addr_parts[1].parse::<u16>().ok()?;

        match proxy_type {
            "HTTP" => Some(ProxyType::Http { host, port }),
            "HTTPS" => Some(ProxyType::Https { host, port }),
            "SOCKS4" => Some(ProxyType::Socks4 { host, port }),
            "SOCKS5" => Some(ProxyType::Socks5 { host, port }),
            "SOCKS" => Some(ProxyType::Socks { host, port }),
            "PROXY" => Some(ProxyType::Generic { host, port }),
            _ => None,
        }
    }

    pub fn to_string(&self) -> String {
        match self {
            ProxyType::Direct => "DIRECT".to_string(),
            ProxyType::Http { host, port } => format!("HTTP {}:{}", host, port),
            ProxyType::Https { host, port } => format!("HTTPS {}:{}", host, port),
            ProxyType::Socks4 { host, port } => format!("SOCKS4 {}:{}", host, port),
            ProxyType::Socks5 { host, port } => format!("SOCKS5 {}:{}", host, port),
            ProxyType::Socks { host, port } => format!("SOCKS {}:{}", host, port),
            ProxyType::Generic { host, port } => format!("PROXY {}:{}", host, port),
            ProxyType::Chain(proxies) => proxies
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join("; "),
        }
    }
}


#[cfg(test)]
mod proxy_parsing_tests {
    use crate::logic::{PacExpression};
    use super::*;

    #[test]
    fn test_compound_proxy_chain() {
        let proxy_str = "PROXY w3proxy.netscape.com:8080; PROXY mozilla.netscape.com:8081";
        let expr = PacExpression::from_proxy_string(proxy_str).unwrap();
        println!("{:?}", expr);

        if let PacExpression::Proxy(ProxyType::Chain(chain)) = expr {
            assert_eq!(chain.len(), 2);

            assert!(matches!(
                &chain[0],
                ProxyType::Generic { host, port }
                if host == "w3proxy.netscape.com" && *port == 8080
            ));

            assert!(matches!(
                &chain[1],
                ProxyType::Generic { host, port }
                if host == "mozilla.netscape.com" && *port == 8081
            ));
        } else {
            panic!("Expected Chain");
        }
    }

    #[test]
    fn test_single_proxy() {
        let proxy_str = "PROXY single.proxy.com:8080";
        let expr = PacExpression::from_proxy_string(proxy_str).unwrap();
        println!("{:?}", expr);

        assert!(matches!(
            expr,
            PacExpression::Proxy(ProxyType::Generic { host, port })
            if host == "single.proxy.com" && port == 8080
        ));
    }

    #[test]
    fn test_direct() {
        let proxy_str = "DIRECT";
        let expr = PacExpression::from_proxy_string(proxy_str).unwrap();
        println!("{:?}", expr);

        assert!(matches!(expr, PacExpression::Proxy(ProxyType::Direct)));
    }

    #[test]
    fn test_mixed_proxy_types_chain() {
        let proxy_str = "PROXY main.proxy.com:8080; SOCKS4 backup.proxy.com:1080; HTTPS secure.proxy.com:443";
        let expr = PacExpression::from_proxy_string(proxy_str).unwrap();
        println!("{:?}", expr);

        if let PacExpression::Proxy(ProxyType::Chain(chain)) = expr {
            assert_eq!(chain.len(), 3);

            assert!(matches!(
                &chain[0],
                ProxyType::Generic { .. }
            ));
            assert!(matches!(
                &chain[1],
                ProxyType::Socks4 { .. }
            ));
            assert!(matches!(
                &chain[2],
                ProxyType::Https { .. }
            ));
        } else {
            panic!("Expected Chain");
        }
    }

    #[test]
    fn test_proxy_chain_roundtrip() {
        let original = "PROXY main.proxy.com:8080; SOCKS4 backup.proxy.com:1080";
        let expr = PacExpression::from_proxy_string(original).unwrap();
        println!("{:?}", expr);

        if let PacExpression::Proxy(proxy) = expr {
            let roundtrip = proxy.to_string();
            assert_eq!(original, roundtrip);
        } else {
            panic!("Expected Proxy");
        }
    }
}


#[cfg(test)]
mod to_js_tests {
    use crate::logic::{ToJs};
    use super::*;

    #[test]
    fn test_proxy_to_js() {
        let proxy = ProxyType::Generic {
            host: "proxy.example.com".to_string(),
            port: 8080,
        };
        let js = proxy.to_js();
        println!("Generated proxy JS:\n{}", js);
        assert_eq!(js, "PROXY proxy.example.com:8080");
    }

    #[test]
    fn test_proxy_chain_to_js() {
        let chain = ProxyType::Chain(vec![
            ProxyType::Generic {
                host: "primary.example.com".to_string(),
                port: 8080,
            },
            ProxyType::Generic {
                host: "backup.example.com".to_string(),
                port: 8080,
            },
        ]);
        let js = chain.to_js();
        println!("Generated proxy chain JS:\n{}", js);
        assert_eq!(js, "PROXY primary.example.com:8080; PROXY backup.example.com:8080");
    }

}
