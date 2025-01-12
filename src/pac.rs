use crate::logic::PacExpression;
use crate::conditions::parse_condition;
use crate::proxy_types::ProxyType;
use boa_engine::ast::expression::literal::Literal;
use boa_engine::ast::scope::Scope;
use boa_engine::ast::statement::{If, Return};
use boa_engine::ast::{Declaration, Expression, Script, Statement, StatementList, StatementListItem};
use boa_engine::interner::Interner;
use boa_engine::parser::Parser;
use boa_engine::Source;

fn build_pac_expression(script: Script, interner: &Interner) -> PacExpression {
    process_statement_list(script.statements(), interner)
}

fn process_statement_list(statement_list: &StatementList, interner: &Interner) -> PacExpression {
    // We'll take the last meaningful expression as the result
    let mut final_expression = PacExpression::Proxy(ProxyType::Direct); // Default fallback

    for statement_item in statement_list.statements().iter() {
        match statement_item {
            StatementListItem::Statement(statement) => {
                if let Some(expr) = process_statement(statement, interner) {
                    final_expression = expr;
                }
            }
            StatementListItem::Declaration(declaration) => {
                if let Some(expr) = process_find_proxy(declaration, interner) {
                    final_expression = expr;
                }
            }
        }
    }

    final_expression
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
        Box::new(process_statement_list(block.statement_list(), interner))
    } else if let Statement::Return(return_statement) = if_stmt.body() {
        Box::new(parse_return(interner, return_statement)
            .unwrap_or(PacExpression::Proxy(ProxyType::Direct)))
    } else {
        Box::new(process_statement_list(
            &StatementList::new(vec![
                StatementListItem::Statement(if_stmt.body().clone())
            ].into_boxed_slice(),
                                false),
            interner))
    };

    // Handle else branch if it exists
    let complete_expression = if let Some(else_stmt) = if_stmt.else_node() {
        let else_body = match else_stmt {
            Statement::Block(block) => {
                process_statement_list(block.statement_list(), interner)
            }
            Statement::Return(return_stmt) => {
                parse_return(interner, return_stmt)
                    .unwrap_or(PacExpression::Proxy(ProxyType::Direct))
            }
            _ => process_statement_list(
                &StatementList::new(vec![
                    StatementListItem::Statement(else_stmt.clone())
                ].into_boxed_slice(),
                                    false),
                interner)
        };

        PacExpression::Condition(Box::new(condition), body, Some(Box::new(else_body)))
    } else {
        PacExpression::Condition(Box::new(condition), body, None)
    };

    Some(complete_expression)
}

fn process_find_proxy(declaration: &Declaration, interner: &Interner) -> Option<PacExpression> {
    if let Declaration::FunctionDeclaration(function_decl) = declaration {
        if let Some(function_name) = interner.resolve(function_decl.name().sym()) {
            if function_name.utf8().unwrap() == "FindProxyForURL" {
                return Some(process_statement_list(function_decl.body().statement_list(), interner));
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
    use crate::conditions::PacCondition;

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
        let pac_expression: PacExpression = build_pac_expression(parse_result, &interner);
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
                    PacExpression::Proxy(ProxyType::Chain(ref chain)) => {
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

        let pac_expression = build_pac_expression(parse_result, &interner);

        // Verify the structure without using box patterns
        match pac_expression {
            PacExpression::Condition(_, if_branch, Some(else_branch)) => {
                assert!(matches!(*if_branch, PacExpression::Proxy(ProxyType::Direct)));

                match *else_branch {
                    PacExpression::Proxy(ProxyType::Chain(ref chain)) => {
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
}

#[test]
fn test_direct_pac_execution() {
    // TODO directly call the pac method
}