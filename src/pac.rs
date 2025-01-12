use crate::logic::PacExpression;
use crate::conditions::{parse_condition, PacCondition};
use crate::proxy_types::ProxyType;
use boa_engine::ast::expression::literal::Literal;
use boa_engine::ast::scope::Scope;
use boa_engine::ast::statement::{If, Return};
use boa_engine::ast::{Declaration, Expression, Script, Statement, StatementList, StatementListItem};
use boa_engine::interner::Interner;
use boa_engine::parser::Parser;
use boa_engine::Source;

fn build_pac_expression(script: Script, interner: &Interner) -> Option<PacExpression> {
    for statement_item in script.statements().iter() {
        match statement_item {
            StatementListItem::Declaration(dec  ) => {
                return process_find_proxy(dec, interner);
            }

            StatementListItem::Statement(statement) => {
                return None;
            }
        }
    }

    None
}

fn process_statement_list(statement_list: &StatementList, interner: &Interner) -> Option<PacExpression> {
    let mut expressions = Vec::new();

    for statement_item in statement_list.statements().iter() {
        match statement_item {
            StatementListItem::Statement(statement) => {
                if let Some(expr) = process_statement(statement, interner) {
                    expressions.push(expr);
                }
            }
            StatementListItem::Declaration(_) => {
                return None;
            }
        }
    }

    match expressions.len() {
        0 => None,
        1 => expressions.pop(),
        _ => Some(PacExpression::Chain(expressions)),
    }
}



fn process_statement(statement: &Statement, interner: &Interner) -> Option<PacExpression> {
    match statement {
        Statement::If(if_stmt) => parse_if_method(interner, &if_stmt),
        Statement::Return(return_stmt) => parse_return(interner, return_stmt),
        _ => None,
    }
}

fn parse_return(interner: &Interner, return_stmt: &Return) -> Option<PacExpression> {
    if let Some(expr) = return_stmt.target().clone() {
        if let Expression::Literal(literal) = expr {
            if let Literal::String(proxy_string) = literal {
                let resolved_proxy_string = interner.resolve(*proxy_string)?.utf8().unwrap();
                PacExpression::from_proxy_string(&resolved_proxy_string)
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    }
}

fn parse_if_method(interner: &Interner, if_stmt: &&If) -> Option<PacExpression> {
    let condition = parse_condition(&if_stmt.cond(), interner)?;

    let body = if let Statement::Block(block) = if_stmt.body() {
       process_statement_list(block.statement_list(), interner)
    } else if let Statement::Return(return_statement) = if_stmt.body() {
        parse_return(interner, return_statement)
    } else {
        process_statement_list(
            &StatementList::new(vec![
                StatementListItem::Statement(if_stmt.body().clone())
            ].into_boxed_slice(),
                                false),
            interner)
    };

    // Handle else branch if it exists
    let complete_expression = if let Some(else_stmt) = if_stmt.else_node() {
        let else_body = match else_stmt {
            Statement::Block(block) => {
                process_statement_list(block.statement_list(), interner)
            }
            Statement::Return(return_stmt) => {
                parse_return(interner, return_stmt)
            }
            _ => process_statement_list(
                &StatementList::new(vec![
                    StatementListItem::Statement(else_stmt.clone())
                ].into_boxed_slice(),
                                    false),
                interner)
        };

        PacExpression::Condition(Box::new(condition), Box::new(body.unwrap()), Some(Box::new(else_body.unwrap())))
    } else {
        PacExpression::Condition(Box::new(condition), Box::new(body.unwrap()), None)
    };

    Some(complete_expression)
}

fn parse_find_proxy_body(statement_list: &StatementList, interner: &Interner) -> PacExpression {
    let mut current_expression = PacExpression::Proxy(ProxyType::Direct);

    for statement_item in statement_list.statements().iter() {
        match statement_item {
            StatementListItem::Statement(statement) => {

                if let Some(expr) = process_statement(statement, interner) {
                    current_expression = build_nested_condition(current_expression, expr);
                }
            }
            _ => {} // Ignore other types of statement list items
        }
    }

    current_expression
}


fn build_nested_condition(current: PacExpression, new_expr: PacExpression) -> PacExpression {
    // Create nested conditions or chain expressions
    match current {
        PacExpression::Condition(condition, if_branch, None) => {
            // If current expression is an incomplete condition, complete it
            PacExpression::Condition(condition, if_branch, Some(Box::new(new_expr)))
        },
        PacExpression::Condition(condition, if_branch, Some(else_branch)) => {
            // If current condition is already complete, nest further
            PacExpression::Condition(
                condition,
                if_branch,
                Some(Box::new(build_nested_condition(*else_branch, new_expr)))
            )
        },
        _ => {
            // For other cases, create a new condition
            PacExpression::Condition(
                Box::new(PacCondition::Boolean(true)),
                Box::new(current),
                Some(Box::new(new_expr))
            )
        }
    }
}


fn process_find_proxy(declaration: &Declaration, interner: &Interner) -> Option<PacExpression> {
    if let Declaration::FunctionDeclaration(function_decl) = declaration {
        if let Some(function_name) = interner.resolve(function_decl.name().sym()) {
            if function_name.utf8().unwrap() == "FindProxyForURL" {
                return process_statement_list(function_decl.body().statement_list(), interner);
            }
        }
    }
    None
}


#[cfg(test)]
mod to_js_tests {

}


#[cfg(test)]
mod pac_files_test {
    use super::*;
    use crate::conditions::{PacCondition, Protocol};
    use crate::logic::ToJs;

    #[test]
    fn test_company_pac_file() {
        let mut interner = Interner::default();

        // Define the PAC file content
        let pac_content = r#"
            function FindProxyForURL(url, host)
            {
                if (isPlainHostName(host) || dnsDomainIs(host, ".company.com"))
                    return "DIRECT";
                else
                    return "PROXY myproxy.company.com:8080; DIRECT";
            }
        "#;

        // Parse the PAC file using boa engine
        let source = Source::from_bytes(pac_content.as_bytes());
        let parse_result = Parser::new(source)
            .parse_script(&Scope::new_global(), &mut interner)
            .expect("Failed to parse PAC file");

        // Process the AST
        let pac_expression: PacExpression = build_pac_expression(parse_result, &interner).unwrap();
        println!("PacExpression:\n{:#?}", pac_expression);
        // Verify the structure
        match pac_expression {
            PacExpression::Condition(condition, if_branch, Some(else_branch)) => {
                // Verify the condition is an OR of isPlainHostName and dnsDomainIs
                match *condition {
                    PacCondition::Or(c1, c2) => {
                        assert!(matches!(*c1, PacCondition::IsPlainHostName()));
                        assert!(matches!(*c2, PacCondition::DnsDomainIs(ref domain)
                            if domain == ".company.com"));
                    }
                    _ => panic!("Expected Or condition"),
                }

                // Verify the if branch returns DIRECT
                assert!(matches!(*if_branch, PacExpression::Proxy(ProxyType::Direct)));

                // Verify the else branch returns the proxy chain
                match *else_branch {
                    PacExpression::Proxy(ProxyType::ProxyFallbackChain(ref chain)) => {
                        assert_eq!(chain.len(), 1);
                        assert!(matches!(
                            &chain[0],
                            ProxyType::Generic { host, port }
                            if host == "myproxy.company.com" && *port == 8080
                        ));
                    }
                    _ => panic!("Expected proxy chain in else branch"),
                }
            }
            _ => panic!("Expected Condition with else branch"),
        }
    }

    #[test]
    fn test_pac_file_with_blocks() {
        let mut interner = Interner::default();

        let pac_content = r#"
        function FindProxyForURL(url, host)
        {
            if (isPlainHostName(host) || dnsDomainIs(host, ".company.com")) {
                return "DIRECT";
            } else {
                return "PROXY myproxy.company.com:8080; DIRECT";
            }
        }
    "#;

        let source = Source::from_bytes(pac_content.as_bytes());
        let parse_result = Parser::new(source)
            .parse_script(&Scope::new_global(), &mut interner)
            .expect("Failed to parse PAC file");

        let pac_expression = build_pac_expression(parse_result, &interner).unwrap();

        match pac_expression {
            PacExpression::Condition(_, if_branch, Some(else_branch)) => {
                assert!(matches!(*if_branch, PacExpression::Proxy(ProxyType::Direct)));

                match *else_branch {
                    PacExpression::Proxy(ProxyType::ProxyFallbackChain(ref chain)) => {
                        assert_eq!(chain.len(), 1);
                        assert!(matches!(
                        &chain[0],
                        ProxyType::Generic { host, port }
                        if host == "myproxy.company.com" && *port == 8080
                    ));
                    }
                    _ => panic!("Expected proxy chain in else branch"),
                }
            }
            _ => panic!("Expected Condition with else branch"),
        }
    }

    #[test]
    fn test_pac_file_with_multiple_conditions() {
        let mut interner = Interner::default();

        let pac_content = r#"
    function FindProxyForURL(url, host)
    {
        if (isInNet(host, "10.0.1.0", "255.255.255.0")) {
            return "DIRECT";
        } else if (url.substring(0, 5) == "http:") {
            return "PROXY 10.0.1.1:3128";
        } else if (url.substring(0, 6) == "https:") {
            return "PROXY 10.0.1.1:3128";
        } else {
            return "DIRECT";
        }
    }
"#;

        let source = Source::from_bytes(pac_content.as_bytes());
        let parse_result = Parser::new(source)
            .parse_script(&Scope::new_global(), &mut interner)
            .expect("Failed to parse PAC file");

        let pac_expression = build_pac_expression(parse_result, &interner).unwrap();
        println!("PacExpression JS:\n{}", pac_expression.to_js());

        // Verify the structure of the PAC expression
        match pac_expression {
            PacExpression::Condition(first_condition, first_branch, Some(second_branch)) => {
                // Check first condition (isInNet)
                assert!(matches!(
                *first_condition,
                PacCondition::IpInNet(ref network, ref mask)
                if network == "10.0.1.0" && mask == "255.255.255.0"
            ));
                assert!(matches!(*first_branch, PacExpression::Proxy(ProxyType::Direct)));

                // Check second (nested) condition
                match *second_branch {
                    PacExpression::Condition(nested_condition, http_branch, Some(https_branch)) => {
                        // Check HTTP condition
                        assert!(matches!(
                        *nested_condition,
                        PacCondition::UrlProtocol(Protocol::Http)
                    ));
                        assert!(matches!(
                        *http_branch,
                        PacExpression::Proxy(ProxyType::Generic { ref host, port })
                        if host == "10.0.1.1" && port == 3128
                    ));

                        // Check HTTPS condition
                        match *https_branch {
                            PacExpression::Condition(https_nested_condition, https_proxy_branch, Some(default_branch)) => {
                                assert!(matches!(
                                *https_nested_condition,
                                PacCondition::UrlProtocol(Protocol::Https)
                            ));
                                assert!(matches!(
                                *https_proxy_branch,
                                PacExpression::Proxy(ProxyType::Generic { ref host, port })
                                if host == "10.0.1.1" && port == 3128
                            ));

                                // Check default DIRECT branch
                                assert!(matches!(
                                *default_branch,
                                PacExpression::Proxy(ProxyType::Direct)
                            ));
                            }
                            _ => panic!("Expected nested HTTPS condition"),
                        }
                    }
                    _ => panic!("Expected nested condition for HTTP/HTTPS"),
                }
            }
            _ => panic!("Expected complex nested condition structure"),
        }
    }

    #[test]
    fn test_pac_file_with_multiple_network_conditions() {
        let mut interner = Interner::default();

        let pac_content = r#"
    function FindProxyForURL(url, host) {
        if (isPlainHostName(host)) return "DIRECT";
        if (shExpMatch(url,"*bluecoat.com*") ||
            shExpMatch(url,"*cacheflow.com*"))
            return "DIRECT";
        if (isInNet(host, "10.0.0.0", "255.0.0.0") ||
            isInNet(host, "172.16.0.0", "255.240.0.0") ||
            isInNet(host, "192.168.0.0", "255.255.0.0") ||
            isInNet(host, "216.52.23.0", "255.255.255.0") ||
            isInNet(host, "127.0.0.0", "255.255.255.0") ||
            isInNet(host, "192.41.79.240", "255.255.255.255"))
            return "DIRECT";
        return "PROXY proxy.threatpulse.net:8080; DIRECT";
        return "PROXY 199.19.250.164:8080; DIRECT";
    }
"#;

        let source = Source::from_bytes(pac_content.as_bytes());
        let parse_result = Parser::new(source)
            .parse_script(&Scope::new_global(), &mut interner)
            .expect("Failed to parse PAC file");

        let pac_expression: PacExpression = build_pac_expression(parse_result, &interner).unwrap();
        println!("PacExpression JS:\n{}", pac_expression.to_js());

        match pac_expression {
            PacExpression::Chain(_) => assert!(true),
            _ => assert!(false),
        }
    }
}