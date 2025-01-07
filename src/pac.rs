use std::fs;
use std::path::Path;
use boa_engine::{Context, Source};
use boa_engine::ast::scope::Scope;
use boa_engine::ast::{Declaration, Expression, Script, Statement, StatementList, StatementListItem};
use boa_engine::ast::expression::literal::Literal;
use boa_engine::ast::function::FunctionBody;
use boa_engine::ast::statement::{If, Return};
use boa_engine::interner::Interner;
use boa_engine::parser::Parser;
use boa_parser::error::ParseResult;

#[derive(Debug, Clone)]
pub enum PacExpression {
    Proxy(String),        // e.g., "PROXY proxy.example.com:8080"
    Direct,               // e.g., "DIRECT"
    Condition(Box<PacCondition>, Box<PacExpression>), // Conditional proxy logic
    Sequence(Vec<PacExpression>),                    // A series of expressions
}

#[derive(Debug, Clone)]
pub enum PacCondition {
    HostMatches(String),  // e.g., `shExpMatch(host, "*.example.com")`
    IpInNet(String, String), // e.g., `isInNet(myIpAddress(), "192.168.0.0", "255.255.255.0")`
    UrlContains(String),  // e.g., `url.indexOf("example")`
    Always,               // Default/fallback case
}

fn build_pac_expression(script: Script, interner: &Interner) -> PacExpression {
    // Process the Script's StatementList
    process_statement_list(script.statements(), interner)
}

fn process_statement_list(statement_list: &StatementList, interner: &Interner) -> PacExpression {
    let mut expressions = vec![];

    for statement_item in statement_list.statements().iter() {
        match statement_item {
            StatementListItem::Statement(statement) => {
                if let Some(expr) = process_statement(statement, interner) {
                    expressions.push(expr);
                }
            }
            StatementListItem::Declaration(declaration) => {
                if let Some(expr) = process_find_proxy(declaration, interner) {
                    expressions.push(expr);
                }
            }
        }
    }

    if expressions.len() == 1 {
        expressions.into_iter().next().unwrap() // Single expression
    } else {
        PacExpression::Sequence(expressions) // Sequence of expressions
    }
}


fn process_statement(statement: &Statement, interner: &Interner) -> Option<PacExpression> {
    match statement {
        Statement::If(if_stmt) => parse_if_method(interner, &if_stmt),
        Statement::Return(return_stmt) => parse_return(interner, return_stmt),
        _ => None,
    }
}

fn parse_return(interner: &Interner, return_stmt: &Return) -> Option<PacExpression>{
    println!("Processing return statement: {:?}", return_stmt);

    if let Some(expr) = return_stmt.target().clone() {
        if let Expression::Literal(literal) = expr {
            if let Literal::String(proxy_string) = literal {
                let resolved_proxy_string = interner.resolve(*proxy_string)?.utf8().unwrap();
                println!("Resolved proxy string: {:?}", resolved_proxy_string);

                if resolved_proxy_string.contains("PROXY") {
                    return Some(PacExpression::Proxy(resolved_proxy_string.clone().to_string()));
                } else if resolved_proxy_string == "DIRECT" {
                    return Some(PacExpression::Direct);
                }
            }
        }
    }
    Some(PacExpression::Direct) // Default fallback
}

fn parse_if_method(interner: &Interner, if_stmt: &&If) -> Option<PacExpression> {
    println!("Processing if statement: {:?}", if_stmt);
    println!("If condition: {:?}", if_stmt.cond());
    println!("If body: {:?}", if_stmt.body());

    let condition = Box::new(parse_condition(&if_stmt.cond()));
    println!("Pac condition: {:?}", condition);

    let body = if let Statement::Block(block) = if_stmt.body() {
        println!("Processing block statement: {:?}", block);

        unimplemented!();
        // Box::new(process_statement_list(block)) // Process as a statement list
    } else if let Statement::Return(return_statement) = if_stmt.body() {
        println!("Processing return statement: {:?}", return_statement);

        unimplemented!();
    } else {
        Box::new(process_statement_list(
            &StatementList::new(vec![
                StatementListItem::Statement(if_stmt.body().clone())].into_boxed_slice(), false), interner))
    };

    Some(PacExpression::Condition(condition, body))
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


fn parse_condition(condition: &Expression) -> PacCondition {
    println!("Condition: {:?}", condition);

    match condition {
        Expression::Call(call_expr) => {
            unimplemented!();

            /*let function_name = call_expr.function().clone();
            let args: Vec<&Literal> = call_expr.args().iter().map(|arg| &arg.literal()).collect();

            match function_name.as_str() {
                "shExpMatch" if args.len() == 2 => {
                    if let Literal::String(pattern) = args[1] {
                        return PacCondition::HostMatches(pattern.clone());
                    }
                }
                "isInNet" if args.len() == 3 => {
                    if let (Literal::String(ip), Literal::String(mask)) = (&args[1], &args[2]) {
                        return PacCondition::IpInNet(ip.clone(), mask.clone());
                    }
                }
                _ => {}
            }*/
        }
        _ => {}
    }
    PacCondition::Always
}

#[test]
fn test_pac_file_parsing() {
    // Path to the PAC file
    let pac_file_path = "./proxy.pac";

    // Check if the PAC file exists
    assert!(
        Path::new(pac_file_path).exists(),
        "PAC file not found at {}",
        pac_file_path
    );

    // Read the file
    let pac_code = fs::read_to_string(pac_file_path).expect("Failed to read proxy.pac file");

    // Set up the Boa parser internals
    let mut interner = Interner::default();
    let source = Source::from_bytes(pac_code.as_bytes());

    // Parse the source code and generate the AST
    let parse_result: ParseResult<Script> = Parser::new(source).parse_script(&Scope::new_global(), &mut interner);
    // Assert that parsing succeeded
    assert!(
        parse_result.is_ok(),
        "PAC file parsing failed: {:?}",
        parse_result.err()
    );
    if let Ok(ast) = parse_result {
        // Convert the AST into a PacExpression
        let pac_expression = build_pac_expression(ast, &interner);

        // Output the resulting PacExpression for debugging
        println!("PacExpression:\n{:#?}", pac_expression);
    }
}