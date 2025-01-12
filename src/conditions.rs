use boa_engine::ast::Expression;
use boa_engine::ast::expression::access::{PropertyAccess, PropertyAccessField};
use boa_engine::ast::expression::Call;
use boa_engine::ast::expression::literal::Literal;
use boa_engine::ast::expression::operator::Binary;
use boa_engine::ast::expression::operator::binary::{BinaryOp, LogicalOp, RelationalOp};
use boa_engine::interner::Interner;
use crate::logic::{PacExpression, ToJs};

#[derive(Debug, Clone, PartialEq)]
pub enum Protocol {
    Http,
    Https,
    Ftp,
}

impl Protocol {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "http:" => Some(Protocol::Http),
            "https:" => Some(Protocol::Https),
            "ftp:" => Some(Protocol::Ftp),
            _ => None,
        }
    }

    pub fn length(&self) -> u32 {
        match self {
            Protocol::Http => 5,  // "http:"
            Protocol::Https => 6, // "https:"
            Protocol::Ftp => 4,   // "ftp:"
        }
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            Protocol::Http => "http:",
            Protocol::Https => "https:",
            Protocol::Ftp => "ftp:",
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Weekday {
    Mon,
    Tue,
    Wed,
    Thu,
    Fri,
    Sat,
    Sun,
}

impl Weekday {
    fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "MON" => Some(Weekday::Mon),
            "TUE" => Some(Weekday::Tue),
            "WED" => Some(Weekday::Wed),
            "THU" => Some(Weekday::Thu),
            "FRI" => Some(Weekday::Fri),
            "SAT" => Some(Weekday::Sat),
            "SUN" => Some(Weekday::Sun),
            _ => None,
        }
    }
}

impl std::fmt::Display for Weekday {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            Weekday::Mon => "MON",
            Weekday::Tue => "TUE",
            Weekday::Wed => "WED",
            Weekday::Thu => "THU",
            Weekday::Fri => "FRI",
            Weekday::Sat => "SAT",
            Weekday::Sun => "SUN",
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Month {
    Jan,
    Feb,
    Mar,
    Apr,
    May,
    Jun,
    Jul,
    Aug,
    Sep,
    Oct,
    Nov,
    Dec,
}

impl Month {
    fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "JAN" => Some(Month::Jan),
            "FEB" => Some(Month::Feb),
            "MAR" => Some(Month::Mar),
            "APR" => Some(Month::Apr),
            "MAY" => Some(Month::May),
            "JUN" => Some(Month::Jun),
            "JUL" => Some(Month::Jul),
            "AUG" => Some(Month::Aug),
            "SEP" => Some(Month::Sep),
            "OCT" => Some(Month::Oct),
            "NOV" => Some(Month::Nov),
            "DEC" => Some(Month::Dec),
            _ => None,
        }
    }
}

impl std::fmt::Display for Month {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            Month::Jan => "JAN",
            Month::Feb => "FEB",
            Month::Mar => "MAR",
            Month::Apr => "APR",
            Month::May => "MAY",
            Month::Jun => "JUN",
            Month::Jul => "JUL",
            Month::Aug => "AUG",
            Month::Sep => "SEP",
            Month::Oct => "OCT",
            Month::Nov => "NOV",
            Month::Dec => "DEC",
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum DateSpec {
    MonthDay { month: Month, day: u8 },
    Month(Month),
    Day(u8),
}

#[derive(Debug, Clone, PartialEq)]
pub enum TimeSpec {
    Hour(u8),
    HourMinute { hour: u8, minute: u8 },
    Gmt(HourMinute),
}

#[derive(Debug, Clone, PartialEq)]
pub struct HourMinute {
    hour: u8,
    minute: u8,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PacCondition {
    HostMatches(String),
    IpInNet(String, String),
    UrlContains(String),
    IsPlainHostName(),
    DnsDomainIs(String),
    Or(Box<PacCondition>, Box<PacCondition>),
    And(Box<PacCondition>, Box<PacCondition>),
    HostEquals(String),
    UrlProtocol(Protocol),
    LocalHostOrDomainIs(String),
    DnsResolve(),
    ConvertAddr(String),
    DnsDomainLevels(),
    WeekdayRange(Weekday, Weekday),
    DateRange(DateSpec, Option<DateSpec>),
    TimeRange(TimeSpec, Option<TimeSpec>),
    IsResolvable(),
    Boolean(bool)
}

impl ToJs for PacCondition {
    fn to_js(&self) -> String {
        match self {
            PacCondition::HostMatches(pattern) =>
                format!("shExpMatch(host, \"{}\")", pattern),
            PacCondition::IpInNet(pattern, mask) =>
                format!("isInNet(myIpAddress(), \"{}\", \"{}\")", pattern, mask),
            PacCondition::UrlContains(text) =>
                format!("url.indexOf(\"{}\") >= 0", text),
            PacCondition::IsPlainHostName() =>
                "isPlainHostName(host)".to_string(),
            PacCondition::DnsDomainIs(domain) =>
                format!("dnsDomainIs(host, \"{}\")", domain),
            PacCondition::Or(left, right) =>
                format!("{} || {}", left.to_js(), right.to_js()),
            PacCondition::And(left, right) =>
                format!("{} && {}", left.to_js(), right.to_js()),
            PacCondition::HostEquals(domain) =>
                format!("host == \"{}\"", domain),
            PacCondition::UrlProtocol(protocol) =>
                format!("url.substring(0, {}) == '{}'", protocol.length(), protocol),
            PacCondition::LocalHostOrDomainIs(domain) =>
                format!("localHostOrDomainIs(host, \"{}\")", domain),
            PacCondition::DnsResolve() =>
                "dnsResolve(host)".to_string(),
            PacCondition::ConvertAddr(ip) =>
                format!("convert_addr({})", ip),
            PacCondition::DnsDomainLevels() =>
                format!("dnsDomainLevels(host)"),
            PacCondition::WeekdayRange(start, end) => {
                format!("weekdayRange(\"{}\", \"{}\")", start, end)
            }
            PacCondition::DateRange(start, Some(end)) => {
                match (start, end) {
                    (DateSpec::MonthDay { month, day }, DateSpec::MonthDay { month: end_month, day: end_day }) => {
                        format!("dateRange(\"{}\", {}, \"{}\", {})", month, day, end_month, end_day)
                    }
                    (DateSpec::Month(month), DateSpec::Month(end_month)) => {
                        format!("dateRange(\"{}\", \"{}\")", month, end_month)
                    }
                    (DateSpec::Day(day), DateSpec::Day(end_day)) => {
                        format!("dateRange({}, {})", day, end_day)
                    }
                    _ => "dateRange()".to_string(), // fallback
                }
            },
            PacCondition::DateRange(start, None) => {
                match start {
                    DateSpec::MonthDay { month, day } => format!("dateRange(\"{}\", {})", month, day),
                    DateSpec::Month(month) => format!("dateRange(\"{}\")", month),
                    DateSpec::Day(day) => format!("dateRange({})", day),
                }
            },
            PacCondition::TimeRange(start, Some(end)) => {
                match (start, end) {
                    (TimeSpec::Hour(h1), TimeSpec::Hour(h2)) => {
                        format!("timeRange({}, {})", h1, h2)
                    }
                    (TimeSpec::HourMinute { hour: h1, minute: m1 },
                        TimeSpec::HourMinute { hour: h2, minute: m2 }) => {
                        format!("timeRange({}, {}, {}, {})", h1, m1, h2, m2)
                    }
                    (TimeSpec::Gmt(t1), TimeSpec::Gmt(t2)) => {
                        format!("timeRange({}, {}, {}, {}, \"GMT\")",
                                t1.hour, t1.minute, t2.hour, t2.minute)
                    }
                    _ => "timeRange()".to_string(), // fallback
                }
            },
            PacCondition::TimeRange(start, None) => {
                match start {
                    TimeSpec::Hour(h) => format!("timeRange({})", h),
                    TimeSpec::HourMinute { hour, minute } => {
                        format!("timeRange({}, {})", hour, minute)
                    }
                    TimeSpec::Gmt(t) => {
                        format!("timeRange({}, {}, \"GMT\")", t.hour, t.minute)
                    }
                }
            },
            PacCondition::IsResolvable() =>
                "isResolvable(host)".to_string(),
            PacCondition::Boolean(value) =>
                value.to_string(),
        }
    }
}

pub fn parse_condition(condition: &Expression, interner: &Interner) -> Option<PacCondition> {
    match condition {
        Expression::Binary(binary) => parse_binary_condition(binary, interner),
        Expression::Call(call_expr) => parse_call_condition(call_expr, interner),
        Expression::Literal(Literal::Bool(value)) => Some(PacCondition::Boolean(*value)),

        _ => None
    }
}

fn parse_binary_condition(binary: &Binary, interner: &Interner) -> Option<PacCondition> {
    match binary.op() {
        BinaryOp::Logical(LogicalOp::Or) => parse_logical_or(binary, interner),
        BinaryOp::Logical(LogicalOp::And) => parse_logical_and(binary, interner),
        BinaryOp::Relational(RelationalOp::Equal) => parse_equality(binary, interner),
        BinaryOp::Relational(RelationalOp::GreaterThanOrEqual) => parse_url_index_of(binary, interner),

        _ => None
    }
}

fn parse_url_index_of(binary: &Binary, interner: &Interner) -> Option<PacCondition> {
    if let Expression::Call(call) = binary.lhs() {
        if let Expression::PropertyAccess(prop_access) = call.function() {
            if let PropertyAccess::Simple(simple_access) = prop_access {
                if let (Expression::Identifier(obj), PropertyAccessField::Const(field_sym)) =
                    (&*simple_access.target(), &simple_access.field()) {
                    let obj_str = interner.resolve_expect(obj.sym()).to_string();
                    let field_str = interner.resolve_expect(*field_sym).to_string();

                    if obj_str == "url" && field_str == "indexOf" {
                        if let Expression::Literal(Literal::Int(index_value)) = binary.rhs() {
                            if *index_value >= 0 {
                                if let Expression::Literal(Literal::String(text)) = &call.args()[0] {
                                    let text_str = interner.resolve_expect(*text).to_string();
                                    return Some(PacCondition::UrlContains(text_str));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

fn parse_logical_or(binary: &Binary, interner: &Interner) -> Option<PacCondition> {
    let lhs = parse_condition(binary.lhs(), interner)?;
    let rhs = parse_condition(binary.rhs(), interner)?;
    Some(PacCondition::Or(Box::new(lhs), Box::new(rhs)))
}

fn parse_logical_and(binary: &Binary, interner: &Interner) -> Option<PacCondition> {
    let lhs = parse_condition(binary.lhs(), interner)?;
    let rhs = parse_condition(binary.rhs(), interner)?;
    Some(PacCondition::And(Box::new(lhs), Box::new(rhs)))
}

fn parse_equality(binary: &Binary, interner: &Interner) -> Option<PacCondition> {
    if let Some(condition) = parse_host_equals(binary, interner) {
        return Some(condition);
    }
    if let Some(condition) = parse_url_protocol(binary, interner) {
        return Some(condition);
    }
    None
}

fn parse_host_equals(binary: &Binary, interner: &Interner) -> Option<PacCondition> {
    if let Expression::Identifier(ident) = binary.lhs() {
        let ident_str = interner.resolve_expect(ident.sym()).to_string();
        if ident_str == "host" {
            if let Expression::Literal(Literal::String(domain)) = binary.rhs() {
                let domain_str = interner.resolve_expect(*domain).to_string();
                return Some(PacCondition::HostEquals(domain_str));
            }
        }
    }
    None
}

fn parse_url_protocol(binary: &Binary, interner: &Interner) -> Option<PacCondition> {
    if let Expression::Call(call) = binary.lhs() {
        if let Expression::PropertyAccess(prop_access) = call.function() {
            if let PropertyAccess::Simple(simple_access) = prop_access {
                if let (Expression::Identifier(obj), PropertyAccessField::Const(field_sym)) =
                    (&*simple_access.target(), &simple_access.field()) {
                    let obj_str = interner.resolve_expect(obj.sym()).to_string();
                    let field_str = interner.resolve_expect(*field_sym).to_string();
                    if obj_str == "url" && field_str == "substring" {
                        let args = call.args();
                        return parse_url_substring(args, binary.rhs(), interner);
                    }
                }
            }
        }
    }
    None
}

fn parse_url_substring(args: &[Expression], rhs: &Expression, interner: &Interner) -> Option<PacCondition> {
    if args.len() == 2 {
        if let Expression::Literal(Literal::Int(length)) = &args[1] {
            if let Expression::Literal(Literal::String(protocol)) = rhs {
                let protocol_str = interner.resolve_expect(*protocol).to_string();
                let length = *length as u32;

                if let Some(protocol) = Protocol::from_str(&protocol_str) {
                    if length == protocol.length() {
                        return Some(PacCondition::UrlProtocol(protocol));
                    }
                }
            }
        }
    }
    None
}

fn parse_call_condition(call_expr: &Call, interner: &Interner) -> Option<PacCondition> {
    if let Expression::Identifier(ident) = call_expr.function() {
        let function_name = interner.resolve_expect(ident.sym()).to_string();
        let args = call_expr.args();

        match function_name.as_str() {
            "isPlainHostName" => parse_is_plain_hostname(args),
            "dnsDomainIs" => parse_dns_domain_is(args, interner),
            "localHostOrDomainIs" => parse_local_host_or_domain_is(args, interner),
            "dnsResolve" => parse_dns_resolve(args),
            "convert_addr" => parse_convert_addr(args, interner),
            "dnsDomainLevels" => parse_dns_domain_levels(args),
            "shExpMatch" => parse_sh_exp_match(args, interner),
            "weekdayRange" => parse_weekday_range(args, interner),
            "dateRange" => parse_date_range(args, interner),
            "timeRange" => parse_time_range(args, interner),
            "isResolvable" => parse_is_resolvable(args),
            "isInNet" => parse_is_in_net(args, interner),
            _ => None
        }
    } else {
        None
    }
}

fn parse_dns_domain_is(args: &[Expression], interner: &Interner) -> Option<PacCondition> {
    if args.len() == 2 {
        if let (Expression::Identifier(_), Expression::Literal(Literal::String(domain))) = (&args[0], &args[1]) {
            let domain = interner.resolve_expect(*domain);
            return Some(PacCondition::DnsDomainIs(domain.to_string()));
        }
    }
    None
}

fn parse_local_host_or_domain_is(args: &[Expression], interner: &Interner) -> Option<PacCondition> {
    if args.len() == 2 {
        if let (Expression::Identifier(_), Expression::Literal(Literal::String(domain))) = (&args[0], &args[1]) {
            let domain_str = interner.resolve_expect(*domain);
            return Some(PacCondition::LocalHostOrDomainIs(domain_str.to_string()));
        }
    }
    None
}

fn parse_dns_resolve(args: &[Expression]) -> Option<PacCondition> {
    if args.len() == 1 && matches!(&args[0], Expression::Identifier(_)) {
        Some(PacCondition::DnsResolve())
    } else {
        None
    }
}

fn parse_convert_addr(args: &[Expression], interner: &Interner) -> Option<PacCondition> {
    if args.len() == 1 {
        if let Expression::Literal(Literal::String(ipaddr)) = &args[0] {
            let ip_str = interner.resolve_expect(*ipaddr);
            return Some(PacCondition::ConvertAddr(ip_str.to_string()));
        }
    }
    None
}

fn parse_dns_domain_levels(args: &[Expression]) -> Option<PacCondition> {
    if args.len() == 1 && matches!(&args[0], Expression::Identifier(_)) {
        Some(PacCondition::DnsDomainLevels())
    } else {
        None
    }
}

fn parse_sh_exp_match(args: &[Expression], interner: &Interner) -> Option<PacCondition> {
    if args.len() == 2 {
        if let Expression::Literal(Literal::String(pattern)) = &args[1] {
            let pattern_str = interner.resolve_expect(*pattern);
            return Some(PacCondition::HostMatches(pattern_str.to_string()));
        }
    }
    None
}

fn parse_weekday_range(args: &[Expression], interner: &Interner) -> Option<PacCondition> {
    if args.len() >= 2 {
        if let (Expression::Literal(Literal::String(day1)), Expression::Literal(Literal::String(day2)))
            = (&args[0], &args[1]) {
            let day1_str = interner.resolve_expect(*day1).to_string();
            let day2_str = interner.resolve_expect(*day2).to_string();
            let weekday1 = Weekday::from_str(&day1_str)?;
            let weekday2 = Weekday::from_str(&day2_str)?;
            return Some(PacCondition::WeekdayRange(weekday1, weekday2));
        }
    }
    None
}

fn parse_is_resolvable(args: &[Expression]) -> Option<PacCondition> {
    if args.len() == 1 && matches!(&args[0], Expression::Identifier(_)) {
        Some(PacCondition::IsResolvable())
    } else {
        None
    }
}

fn parse_is_in_net(args: &[Expression], interner: &Interner) -> Option<PacCondition> {
    if args.len() == 3 {
        if let (Expression::Literal(Literal::String(ip)), Expression::Literal(Literal::String(mask)))
            = (&args[1], &args[2]) {
            let ip_str = interner.resolve_expect(*ip);
            let mask_str = interner.resolve_expect(*mask);
            return Some(PacCondition::IpInNet(ip_str.to_string(), mask_str.to_string()));
        }
    }
    None
}

// Individual parse functions for each call type
fn parse_is_plain_hostname(args: &[Expression]) -> Option<PacCondition> {
    if args.len() == 1 && matches!(&args[0], Expression::Identifier(_)) {
        Some(PacCondition::IsPlainHostName())
    } else {
        None
    }
}

fn parse_date_range(args: &[Expression], interner: &Interner) -> Option<PacCondition> {
    match args.len() {
        // dateRange("JAN", "MAR") or dateRange(1, 15)
        2 => {
            match (&args[0], &args[1]) {
                (Expression::Literal(Literal::String(m1)), Expression::Literal(Literal::String(m2))) => {
                    let month1 = Month::from_str(interner.resolve_expect(*m1).utf8().unwrap())?;
                    let month2 = Month::from_str(interner.resolve_expect(*m2).utf8().unwrap())?;
                    Some(PacCondition::DateRange(
                        DateSpec::Month(month1),
                        Some(DateSpec::Month(month2))
                    ))
                },
                (Expression::Literal(Literal::Int(d1)), Expression::Literal(Literal::Int(d2))) => {
                    let day1 = *d1 as u8;
                    let day2 = *d2 as u8;
                    if day1 > 31 || day2 > 31 {
                        return None;
                    }
                    Some(PacCondition::DateRange(
                        DateSpec::Day(day1),
                        Some(DateSpec::Day(day2))
                    ))
                },
                _ => None
            }
        },
        // dateRange("JUN") - single month
        1 => {
            if let Expression::Literal(Literal::String(month)) = &args[0] {
                let month = Month::from_str(interner.resolve_expect(*month).utf8().unwrap())?;
                Some(PacCondition::DateRange(
                    DateSpec::Month(month),
                    None
                ))
            } else {
                None
            }
        },
        // dateRange("JAN", 1, "DEC", 31)
        4 => {
            match (&args[0], &args[1], &args[2], &args[3]) {
                (
                    Expression::Literal(Literal::String(m1)),
                    Expression::Literal(Literal::Int(d1)),
                    Expression::Literal(Literal::String(m2)),
                    Expression::Literal(Literal::Int(d2))
                ) => {
                    let month1 = Month::from_str(interner.resolve_expect(*m1).utf8().unwrap())?;
                    let day1 = *d1 as u8;
                    let month2 = Month::from_str(interner.resolve_expect(*m2).utf8().unwrap())?;
                    let day2 = *d2 as u8;

                    if day1 > 31 || day2 > 31 {
                        return None;
                    }

                    Some(PacCondition::DateRange(
                        DateSpec::MonthDay { month: month1, day: day1 },
                        Some(DateSpec::MonthDay { month: month2, day: day2 })
                    ))
                },
                _ => None
            }
        },
        _ => None
    }
}

fn parse_time_range(args: &[Expression], interner: &Interner) -> Option<PacCondition> {
    match args.len() {
        // timeRange(12) - single hour
        1 => {
            if let Expression::Literal(Literal::Int(hour)) = args[0] {
                let hour = hour as u8;
                if hour > 23 {
                    return None;
                }
                Some(PacCondition::TimeRange(
                    TimeSpec::Hour(hour),
                    None
                ))
            } else {
                None
            }
        },
        // timeRange(9, 17) - hour range
        2 => {
            match (&args[0], &args[1]) {
                (Expression::Literal(Literal::Int(h1)), Expression::Literal(Literal::Int(h2))) => {
                    let hour1 = *h1 as u8;
                    let hour2 = *h2 as u8;
                    if hour1 > 23 || hour2 > 23 {
                        return None;
                    }
                    Some(PacCondition::TimeRange(
                        TimeSpec::Hour(hour1),
                        Some(TimeSpec::Hour(hour2))
                    ))
                },
                _ => None
            }
        },

        // timeRange(9, 30, 17, 45) - hour and minute range
        4 => {
            match (&args[0], &args[1], &args[2], &args[3]) {
                (
                    Expression::Literal(Literal::Int(h1)),
                    Expression::Literal(Literal::Int(m1)),
                    Expression::Literal(Literal::Int(h2)),
                    Expression::Literal(Literal::Int(m2))
                ) => {
                    let hour1 = *h1 as u8;
                    let min1 = *m1 as u8;
                    let hour2 = *h2 as u8;
                    let min2 = *m2 as u8;

                    if hour1 > 23 || hour2 > 23 || min1 > 59 || min2 > 59 {
                        return None;
                    }

                    Some(PacCondition::TimeRange(
                        TimeSpec::HourMinute { hour: hour1, minute: min1 },
                        Some(TimeSpec::HourMinute { hour: hour2, minute: min2 })
                    ))
                },
                _ => None
            }
        },
        // timeRange(9, 30, 17, 45, "GMT")
        5 => {
            match (&args[0], &args[1], &args[2], &args[3], &args[4]) {
                (
                    Expression::Literal(Literal::Int(h1)),
                    Expression::Literal(Literal::Int(m1)),
                    Expression::Literal(Literal::Int(h2)),
                    Expression::Literal(Literal::Int(m2)),
                    Expression::Literal(Literal::String(tz))
                ) => {
                    let timezone = interner.resolve_expect(*tz);
                    if timezone.utf8().unwrap() != "GMT" {
                        return None;
                    }

                    let hour1 = *h1 as u8;
                    let min1 = *m1 as u8;
                    let hour2 = *h2 as u8;
                    let min2 = *m2 as u8;

                    if hour1 > 23 || hour2 > 23 || min1 > 59 || min2 > 59 {
                        return None;
                    }

                    Some(PacCondition::TimeRange(
                        TimeSpec::Gmt(HourMinute { hour: hour1, minute: min1 }),
                        Some(TimeSpec::Gmt(HourMinute { hour: hour2, minute: min2 }))
                    ))
                },
                _ => None
            }
        },
        _ => None
    }
}

fn parse_url_contains(args: &[Expression], interner: &Interner) -> Option<PacCondition> {
    if args.len() == 1 {
        if let Expression::Literal(Literal::String(text)) = &args[0] {
            let text_str = interner.resolve_expect(*text);
            return Some(PacCondition::UrlContains(text_str.to_string()));
        }
    }
    None
}


#[cfg(test)]
mod condition_tests {
    use boa_engine::ast::{Statement, StatementListItem};
    use boa_engine::ast::scope::Scope;
    use boa_parser::{Parser, Source};
    use crate::conditions::{PacCondition, Protocol};
    use super::*;

    fn parse_test_condition(code: &str) -> Option<PacCondition> {
        let mut interner = Interner::default();
        let source = Source::from_bytes(code.as_bytes());
        let parse_result = Parser::new(source)
            .parse_script(&Scope::new_global(), &mut interner)
            .expect("Failed to parse condition");

        if let StatementListItem::Statement(Statement::Expression(expr)) =
            &parse_result.statements().statements()[0] {
            parse_condition(expr, &interner)
        } else {
            panic!("Expected expression statement");
        }
    }

    #[test]
    fn test_plain_hostname() {
        let condition = r#"isPlainHostName(host)"#;
        let result = parse_test_condition(condition).unwrap();
        println!("Parsed isPlainHostName: {:?}", result);
        assert!(matches!(result, PacCondition::IsPlainHostName()));
    }

    #[test]
    fn test_dns_domain_is() {
        let condition = r#"dnsDomainIs(host, ".company.com")"#;
        let result = parse_test_condition(condition).unwrap();
        println!("Parsed dnsDomainIs: {:?}", result);
        assert!(matches!(result, PacCondition::DnsDomainIs(d) if d == ".company.com"));
    }

    #[test]
    fn test_local_host_or_domain_is() {
        let condition = r#"localHostOrDomainIs(host, "localhost")"#;
        let result = parse_test_condition(condition).unwrap();
        println!("Parsed localHostOrDomainIs: {:?}", result);
        assert!(matches!(result, PacCondition::LocalHostOrDomainIs(d) if d == "localhost"));
    }

    #[test]
    fn test_dns_resolve() {
        let condition = r#"dnsResolve(host)"#;
        let result = parse_test_condition(condition).unwrap();
        println!("Parsed dnsResolve: {:?}", result);
        assert!(matches!(result, PacCondition::DnsResolve()));
    }

    #[test]
    fn test_convert_addr() {
        let condition = r#"convert_addr("192.168.1.1")"#;
        let result = parse_test_condition(condition).unwrap();
        println!("Parsed convert_addr: {:?}", result);
        assert!(matches!(result, PacCondition::ConvertAddr(ip) if ip == "192.168.1.1"));
    }

    #[test]
    fn test_dns_domain_levels() {
        let condition = r#"dnsDomainLevels(host)"#;
        let result = parse_test_condition(condition).unwrap();
        println!("Parsed dnsDomainLevels: {:?}", result);
        assert!(matches!(result, PacCondition::DnsDomainLevels()));
    }

    #[test]
    fn test_sh_exp_match() {
        let condition = r#"shExpMatch(host, "*.example.com")"#;
        let result = parse_test_condition(condition).unwrap();
        println!("Parsed shExpMatch: {:?}", result);
        assert!(matches!(result, PacCondition::HostMatches(p) if p == "*.example.com"));
    }

    #[test]
    fn test_weekday_range() {
        let condition = r#"weekdayRange("MON", "FRI")"#;
        let result = parse_test_condition(condition).unwrap();
        assert!(matches!(
            result,
            PacCondition::WeekdayRange(Weekday::Mon, Weekday::Fri)
        ));

        assert_eq!(
            result.to_js(),
            "weekdayRange(\"MON\", \"FRI\")"
        );

        // Invalid weekday
        let condition = r#"weekdayRange("INVALID", "FRI")"#;
        assert!(parse_test_condition(condition).is_none());
    }

    #[test]
    fn test_weekday_parsing() {
        assert_eq!(Weekday::from_str("MON"), Some(Weekday::Mon));
        assert_eq!(Weekday::from_str("TUE"), Some(Weekday::Tue));
        assert_eq!(Weekday::from_str("mon"), Some(Weekday::Mon));
        assert_eq!(Weekday::from_str("INVALID"), None);
    }

    #[test]
    fn test_date_range_month_only() {
        let condition = r#"dateRange("JAN", "MAR")"#;
        let result = parse_test_condition(condition).unwrap();
        assert!(matches!(
            result,
            PacCondition::DateRange(
                DateSpec::Month(Month::Jan),
                Some(DateSpec::Month(Month::Mar))
            )
        ));
        assert_eq!(result.to_js(), r#"dateRange("JAN", "MAR")"#);
    }

    #[test]
    fn test_date_range_single_month() {
        let condition = r#"dateRange("JUN")"#;
        let result = parse_test_condition(condition).unwrap();
        assert!(matches!(
            result,
            PacCondition::DateRange(
                DateSpec::Month(Month::Jun),
                None
            )
        ));
        assert_eq!(result.to_js(), r#"dateRange("JUN")"#);
    }

    #[test]
    fn test_date_range_full_date() {
        let condition = r#"dateRange("JAN", 1, "DEC", 31)"#;
        let result = parse_test_condition(condition).unwrap();
        assert!(matches!(
            result,
            PacCondition::DateRange(
                DateSpec::MonthDay { month: Month::Jan, day: 1 },
                Some(DateSpec::MonthDay { month: Month::Dec, day: 31 })
            )
        ));
        assert_eq!(result.to_js(), r#"dateRange("JAN", 1, "DEC", 31)"#);
    }

    #[test]
    fn test_date_range_day_only() {
        let condition = r#"dateRange(1, 15)"#;
        let result = parse_test_condition(condition).unwrap();
        assert!(matches!(
            result,
            PacCondition::DateRange(
                DateSpec::Day(1),
                Some(DateSpec::Day(15))
            )
        ));
        assert_eq!(result.to_js(), "dateRange(1, 15)");
    }

    #[test]
    fn test_invalid_date_range() {
        let condition = r#"dateRange("INVALID", "MAR")"#;
        assert!(parse_test_condition(condition).is_none());

        let condition = r#"dateRange("JAN", 32)"#;  // Invalid day
        assert!(parse_test_condition(condition).is_none());
    }

    #[test]
    fn test_time_range_hours() {
        let condition = r#"timeRange(9, 17)"#;  // 9 AM to 5 PM
        let result = parse_test_condition(condition).unwrap();
        println!("Parsed timeRange: {:?}", result);

        assert!(matches!(
            result,
            PacCondition::TimeRange(
                TimeSpec::Hour(9),
                Some(TimeSpec::Hour(17))
            )
        ));
        assert_eq!(result.to_js(), "timeRange(9, 17)");
    }

    #[test]
    fn test_time_range_hours_minutes() {
        let condition = r#"timeRange(9, 30, 17, 45)"#;  // 9:30 AM to 5:45 PM
        let result = parse_test_condition(condition).unwrap();
        assert!(matches!(
            result,
            PacCondition::TimeRange(
                TimeSpec::HourMinute { hour: 9, minute: 30 },
                Some(TimeSpec::HourMinute { hour: 17, minute: 45 })
            )
        ));
        assert_eq!(result.to_js(), "timeRange(9, 30, 17, 45)");
    }

    #[test]
    fn test_time_range_gmt() {
        let condition = r#"timeRange(9, 30, 17, 45, "GMT")"#;
        let result = parse_test_condition(condition).unwrap();
        assert!(matches!(
            result,
            PacCondition::TimeRange(
                TimeSpec::Gmt(HourMinute { hour: 9, minute: 30 }),
                Some(TimeSpec::Gmt(HourMinute { hour: 17, minute: 45 }))
            )
        ));
        assert_eq!(result.to_js(), "timeRange(9, 30, 17, 45, \"GMT\")");
    }

    #[test]
    fn test_single_time_spec() {
        let condition = r#"timeRange(12)"#;  // Noon
        let result = parse_test_condition(condition).unwrap();
        assert!(matches!(
            result,
            PacCondition::TimeRange(
                TimeSpec::Hour(12),
                None
            )
        ));
        assert_eq!(result.to_js(), "timeRange(12)");

        let condition = r#"timeRange(12, 16)"#;  // 12:30
        let result = parse_test_condition(condition).unwrap();
        assert!(matches!(
            result,
            PacCondition::TimeRange(
                TimeSpec::Hour (12 ),
                Some(TimeSpec::Hour(16)),
            )
        ));
        assert_eq!(result.to_js(), "timeRange(12, 16)");
    }

    #[test]
    fn test_invalid_time_range() {
        let condition = r#"timeRange(25, 0)"#;  // Invalid hour
        assert!(parse_test_condition(condition).is_none());

        let condition = r#"timeRange(12, 60)"#;  // Invalid minute
        assert!(parse_test_condition(condition).is_none());

        let condition = r#"timeRange(9, 30, 17, 45, "UTC")"#;  // Invalid timezone
        assert!(parse_test_condition(condition).is_none());
    }

    #[test]
    fn test_host_equals() {
        let condition = r#"host == "download.microsoft.com""#;
        let result = parse_test_condition(condition).unwrap();
        println!("Parsed host equals: {:?}", result);
        assert!(matches!(result, PacCondition::HostEquals(h) if h == "download.microsoft.com"));
    }

    #[test]
    fn test_is_resolvable() {
        let condition = r#"isResolvable(host)"#;
        let result = parse_test_condition(condition).unwrap();
        println!("Parsed isResolvable: {:?}", result);
        assert!(matches!(result, PacCondition::IsResolvable()));
    }

    #[test]
    fn test_is_in_net() {
        let condition = r#"isInNet(myIpAddress(), "192.168.0.0", "255.255.0.0")"#;
        let result = parse_test_condition(condition).unwrap();
        println!("Parsed isInNet: {:?}", result);
        assert!(matches!(result, PacCondition::IpInNet(pattern, mask) if pattern == "192.168.0.0" && mask == "255.255.0.0"));
    }

    #[test]
    fn test_boolean() {
        let condition = "true";
        let result = parse_test_condition(condition).unwrap();
        println!("Parsed boolean: {:?}", result);
        assert!(matches!(result, PacCondition::Boolean(true)));
    }

    #[test]
    fn test_logical_operators() {
        let condition = r#"isPlainHostName(host) && dnsDomainIs(host, ".company.com")"#;
        let result = parse_test_condition(condition).unwrap();
        println!("Parsed AND condition: {:?}", result);
        assert!(matches!(result, PacCondition::And(_, _)));

        let condition = r#"isPlainHostName(host) || dnsDomainIs(host, ".company.com")"#;
        let result = parse_test_condition(condition).unwrap();
        println!("Parsed OR condition: {:?}", result);
        assert!(matches!(result, PacCondition::Or(_, _)));
    }

    #[test]
    fn test_url_protocol() {
        let condition = r#"url.substring(0, 5) == "http:""#;
        let result = parse_test_condition(condition).unwrap();
        println!("Parsed URL protocol: {:?}", result);
        assert!(matches!(result, PacCondition::UrlProtocol(Protocol::Http)));

        // Test invalid length
        let condition = r#"url.substring(0, 6) == "http:""#;
        assert!(parse_test_condition(condition).is_none());

        // Test all protocols
        let test_cases = vec![
            (r#"url.substring(0, 5) == "http:""#, Protocol::Http),
            (r#"url.substring(0, 6) == "https:""#, Protocol::Https),
            (r#"url.substring(0, 4) == "ftp:""#, Protocol::Ftp),
        ];

        for (condition, expected_protocol) in test_cases {
            let result = parse_test_condition(condition).unwrap();
            assert!(matches!(
                result,
                PacCondition::UrlProtocol(protocol) if protocol == expected_protocol
            ));
        }

        let condition = r#"url.substring(0, 5) == "gttp:""#;
        assert!(parse_test_condition(condition).is_none());
    }

    #[test]
    fn test_url_contains() {
        let condition = r#"url.indexOf("example") >= 0"#;
        let result = parse_test_condition(condition).unwrap();

        assert!(matches!(
            result,
            PacCondition::UrlContains(ref text) if text == "example"
        ));
        assert_eq!(result.to_js(), r#"url.indexOf("example") >= 0"#);

        // Additional test with a different string
        let condition = r#"url.indexOf("test.com") >= 0"#;
        let result = parse_test_condition(condition).unwrap();

        assert!(matches!(
        result,
        PacCondition::UrlContains(ref text) if text == "test.com"
    ));
        assert_eq!(result.to_js(), r#"url.indexOf("test.com") >= 0"#);
    }
}


#[cfg(test)]
mod to_js_tests {
    use crate::logic::{ToJs};
    use crate::proxy_types::ProxyType;
    use super::*;

    #[test]
    fn test_condition_to_js() {
        let condition = PacCondition::Or(
            Box::new(PacCondition::IsPlainHostName()),
            Box::new(PacCondition::DnsDomainIs(".company.com".to_string()))
        );
        let js = condition.to_js();
        println!("Generated condition JS:\n{}", js);
        assert_eq!(js, "(isPlainHostName(host)) || (dnsDomainIs(host, \".company.com\"))");
    }

    #[test]
    fn test_expression_to_js() {
        let expr = PacExpression::Condition(
            Box::new(PacCondition::IsPlainHostName()),
            Box::new(PacExpression::Proxy(ProxyType::Direct)),
            Some(Box::new(PacExpression::Proxy(ProxyType::Generic {
                host: "proxy.example.com".to_string(),
                port: 8080,
            })))
        );
        let js = expr.to_js();
        println!("Generated expression JS:\n{}", js);
        assert_eq!(js, "if (isPlainHostName(host)) { return \"DIRECT\"; } else { return \"PROXY proxy.example.com:8080\"; }");
    }

    #[test]
    fn test_complex_condition_to_js() {
        let condition = PacCondition::And(
            Box::new(PacCondition::IsPlainHostName()),
            Box::new(PacCondition::Or(
                Box::new(PacCondition::DnsDomainIs(".company.com".to_string())),
                Box::new(PacCondition::IpInNet("10.0.0.0".to_string(), "255.0.0.0".to_string()))
            ))
        );
        let js = condition.to_js();
        println!("Generated complex condition JS:\n{}", js);
        assert_eq!(
            js,
            "(isPlainHostName(host)) && ((dnsDomainIs(host, \".company.com\")) || (isInNet(myIpAddress(), \"10.0.0.0\", \"255.0.0.0\")))"
        );
    }

}
