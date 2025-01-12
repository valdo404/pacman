use crate::logic::ProxyType::Direct;
use crate::conditions::PacCondition;
use crate::proxy_types::ProxyType;

pub trait ToJs {
    fn to_js(&self) -> String;
}

#[derive(Debug, Clone, PartialEq)]
pub enum PacExpression {
    Proxy(ProxyType),
    Condition(Box<PacCondition>, Box<PacExpression>, Option<Box<PacExpression>>), // condition, if_branch, else_branch
}

impl ToJs for PacExpression {
    fn to_js(&self) -> String {
        match self {
            PacExpression::Proxy(proxy) => format!("return \"{}\";", proxy.to_js()),
            PacExpression::Condition(cond, if_branch, else_branch) => {
                let mut js = format!("if ({}) {{ {} }}", cond.to_js(), if_branch.to_js());
                if let Some(else_expr) = else_branch {
                    js.push_str(&format!(" else {{ {} }}", else_expr.to_js()));
                }
                js
            }
        }
    }
}

impl PacExpression {
    pub fn from_proxy_string(proxy_str: &str) -> Option<PacExpression> {
        if proxy_str == "DIRECT" {
            return Some(PacExpression::Proxy(Direct));
        }

        ProxyType::from_str(proxy_str).map(PacExpression::Proxy)
    }
}
