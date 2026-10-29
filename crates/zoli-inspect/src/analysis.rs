use crate::{Finding, Report};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use oxc_allocator::Allocator;
use oxc_ast::ast::*;
use oxc_ast_visit::{Visit, walk};
use oxc_semantic::{Scoping, SemanticBuilder};
use oxc_span::SourceType;
use oxc_syntax::{scope::ScopeFlags, symbol::SymbolId};
use std::collections::HashMap;

#[derive(Clone, Default)]
struct Flow {
    secret: bool,
    remote: bool,
    decoded: u8,
    path: bool,
    literal: Option<String>,
    symbol: Option<String>,
    steps: Vec<String>,
}
impl Flow {
    fn merge(&mut self, other: Self) {
        self.secret |= other.secret;
        self.remote |= other.remote;
        self.decoded = self.decoded.max(other.decoded);
        self.path |= other.path;
        for s in other.steps {
            if self.steps.len() < 8 && !self.steps.contains(&s) {
                self.steps.push(s);
            }
        }
    }
    fn symbol(value: &str) -> Self {
        Self {
            symbol: Some(
                value
                    .strip_prefix("node:")
                    .unwrap_or(value)
                    .replace("fs/promises", "fs.promises"),
            ),
            ..Default::default()
        }
    }
}
fn sensitive(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [
        ".npmrc",
        ".netrc",
        ".ssh/",
        ".aws/credentials",
        "application_default_credentials.json",
    ]
    .iter()
    .any(|p| lower.contains(p))
}
fn secret_env(value: &str) -> bool {
    let upper = value.to_ascii_uppercase();
    [
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "PRIVATE_KEY",
        "ACCESS_KEY",
        "CREDENTIAL",
    ]
    .iter()
    .any(|p| upper.contains(p))
}
fn network(name: &str) -> bool {
    matches!(
        name,
        "fetch"
            | "http.get"
            | "https.get"
            | "http.request"
            | "https.request"
            | "axios.post"
            | "axios.put"
            | "axios.request"
            | "undici.fetch"
            | "undici.request"
            | "node-fetch"
            | "got"
            | "got.post"
    )
}
fn execution(name: &str) -> bool {
    matches!(
        name,
        "eval"
            | "Function"
            | "child_process.exec"
            | "child_process.execSync"
            | "child_process.spawn"
            | "child_process.spawnSync"
            | "vm.runInContext"
            | "vm.runInNewContext"
            | "vm.runInThisContext"
            | "vm.Script"
    )
}

pub(super) fn scan(file: &str, source: &str, line_offset: usize, report: &mut Report) {
    let allocator = Allocator::default();
    let source_type = SourceType::from_path(file)
        .unwrap_or(SourceType::unambiguous())
        .with_unambiguous(true);
    let parsed = oxc_parser::Parser::new(&allocator, source, source_type)
        .with_options(oxc_parser::ParseOptions {
            allow_return_outside_function: true,
            ..Default::default()
        })
        .parse();
    if parsed.panicked || !parsed.errors.is_empty() || parsed.is_flow_language {
        report
            .gaps
            .push(format!("unsupported_or_invalid_source:{file}"));
        return;
    }
    let semantic = SemanticBuilder::new()
        .with_check_syntax_error(true)
        .build(&parsed.program);
    if !semantic.errors.is_empty() {
        report.gaps.push(format!("semantic_syntax_error:{file}"));
        return;
    }
    let mut visitor = Scanner {
        file,
        source,
        line_offset,
        report,
        scoping: semantic.semantic.scoping(),
        values: HashMap::new(),
        nodes: 0,
    };
    // Static import/module aliases are available to functions regardless of the
    // textual order of their declarations. No package module is imported.
    for statement in &parsed.program.body {
        if let Statement::ImportDeclaration(import) = statement {
            visitor.visit_import_declaration(import);
        }
        if let Statement::VariableDeclaration(declaration) = statement {
            for d in &declaration.declarations {
                if let Some(init) = &d.init {
                    let value = visitor.value(init, 0);
                    if value.symbol.is_some() {
                        visitor.bind(&d.id, value);
                    }
                }
            }
        }
    }
    visitor.visit_program(&parsed.program);
}
struct Scanner<'s> {
    file: &'s str,
    source: &'s str,
    line_offset: usize,
    report: &'s mut Report,
    scoping: &'s Scoping,
    values: HashMap<SymbolId, Flow>,
    nodes: usize,
}
impl Scanner<'_> {
    fn line(&self, position: u32) -> usize {
        self.line_offset
            + 1
            + self.source.as_bytes()[..(position as usize).min(self.source.len())]
                .iter()
                .filter(|b| **b == b'\n')
                .count()
    }
    fn gap(&mut self, reason: &str) {
        let gap = format!("{reason}:{}", self.file);
        if !self.report.gaps.contains(&gap) {
            self.report.gaps.push(gap);
        }
    }
    fn reference(&self, id: &IdentifierReference<'_>) -> Option<SymbolId> {
        id.reference_id
            .get()
            .and_then(|r| self.scoping.get_reference(r).symbol_id())
    }
    fn identifier(&self, id: &IdentifierReference<'_>) -> Flow {
        if let Some(symbol) = self.reference(id) {
            return self.values.get(&symbol).cloned().unwrap_or_default();
        }
        if [
            "require", "process", "fetch", "eval", "Function", "Buffer", "atob", "JSON",
        ]
        .contains(&id.name.as_str())
        {
            Flow::symbol(id.name.as_str())
        } else {
            Flow::default()
        }
    }
    fn member(&self, mut object: Flow, property: &str) -> Flow {
        if object.symbol.as_deref() == Some("process") && property == "env" {
            object.secret = true;
            object.steps.push("environment collection access".into());
        } else if object.symbol.as_deref() == Some("process.env") {
            object.secret = secret_env(property);
            if object.secret {
                object.steps.push("credential environment access".into());
            }
        }
        object.symbol = object.symbol.map(|s| format!("{s}.{property}"));
        object.literal = None;
        object
    }
    fn bind(&mut self, pattern: &BindingPattern<'_>, value: Flow) {
        match pattern {
            BindingPattern::BindingIdentifier(id) => {
                if let Some(symbol) = id.symbol_id.get() {
                    self.values.insert(symbol, value);
                }
            }
            BindingPattern::ObjectPattern(object) => {
                for property in &object.properties {
                    if let Some(name) = property.key.static_name() {
                        let member = self.member(value.clone(), &name);
                        self.bind(&property.value, member);
                    }
                }
            }
            BindingPattern::AssignmentPattern(p) => self.bind(&p.left, value),
            _ => {}
        }
    }
    fn value(&mut self, expression: &Expression<'_>, depth: usize) -> Flow {
        if depth > 64 {
            self.gap("expression_flow_limit");
            return Flow::default();
        }
        let depth = depth + 1;
        match expression.get_inner_expression() {
            Expression::StringLiteral(s) => {
                if s.value.len() > 65536 {
                    return Flow {
                        path: sensitive(&s.value),
                        ..Default::default()
                    };
                }
                Flow {
                    literal: Some(s.value.to_string()),
                    path: sensitive(&s.value),
                    ..Default::default()
                }
            }
            Expression::Identifier(id) => self.identifier(id),
            Expression::StaticMemberExpression(m) => {
                let object = self.value(&m.object, depth);
                self.member(object, m.property.name.as_str())
            }
            Expression::ComputedMemberExpression(m) => {
                let object = self.value(&m.object, depth);
                let property = self.value(&m.expression, depth);
                property
                    .literal
                    .map_or(object.clone(), |p| self.member(object, &p))
            }
            Expression::AwaitExpression(e) => self.value(&e.argument, depth),
            Expression::BinaryExpression(e)
                if e.operator == oxc_syntax::operator::BinaryOperator::Addition =>
            {
                let mut left = self.value(&e.left, depth);
                let right = self.value(&e.right, depth);
                let literal = match (&left.literal, &right.literal) {
                    (Some(a), Some(b)) if a.len() + b.len() <= 65536 => Some(format!("{a}{b}")),
                    _ => None,
                };
                left.merge(right);
                left.literal = literal;
                left.symbol = None;
                left
            }
            Expression::TemplateLiteral(t) => {
                let mut value = Flow::default();
                let mut literal = String::new();
                let mut known = true;
                for (i, q) in t.quasis.iter().enumerate() {
                    if let Some(s) = &q.value.cooked {
                        if literal.len() + s.len() <= 65536 {
                            literal.push_str(s);
                        } else {
                            known = false;
                        }
                    } else {
                        known = false;
                    }
                    if let Some(e) = t.expressions.get(i) {
                        let e = self.value(e, depth);
                        if let Some(s) = &e.literal {
                            if literal.len() + s.len() <= 65536 {
                                literal.push_str(s);
                            } else {
                                known = false;
                            }
                        } else {
                            known = false;
                        }
                        value.merge(e);
                    }
                }
                if known {
                    value.path |= sensitive(&literal);
                    value.literal = Some(literal);
                }
                value
            }
            Expression::CallExpression(c) => self.call_value(c, depth),
            Expression::ObjectExpression(o) => {
                let mut value = Flow::default();
                for property in &o.properties {
                    match property {
                        ObjectPropertyKind::ObjectProperty(p) => {
                            value.merge(self.value(&p.value, depth))
                        }
                        ObjectPropertyKind::SpreadProperty(p) => {
                            value.merge(self.value(&p.argument, depth))
                        }
                    }
                }
                value
            }
            Expression::ArrayExpression(a) => {
                let mut value = Flow::default();
                for e in &a.elements {
                    if let Some(e) = e.as_expression() {
                        value.merge(self.value(e, depth));
                    }
                }
                value
            }
            Expression::ConditionalExpression(c) => {
                let mut v = self.value(&c.consequent, depth);
                v.merge(self.value(&c.alternate, depth));
                v
            }
            Expression::LogicalExpression(c) => {
                let mut v = self.value(&c.left, depth);
                v.merge(self.value(&c.right, depth));
                v
            }
            _ => Flow::default(),
        }
    }
    fn arguments(
        &mut self,
        args: &oxc_allocator::Vec<'_, Argument<'_>>,
        depth: usize,
    ) -> Vec<Flow> {
        args.iter()
            .map(|a| {
                a.as_expression()
                    .map(|e| self.value(e, depth))
                    .unwrap_or_default()
            })
            .collect()
    }
    fn call_value(&mut self, call: &CallExpression<'_>, depth: usize) -> Flow {
        let callee = self.value(&call.callee, depth);
        let name = callee.symbol.as_deref().unwrap_or_default();
        let arguments = self.arguments(&call.arguments, depth);
        if name == "require" {
            return arguments
                .first()
                .and_then(|a| a.literal.as_deref())
                .map(Flow::symbol)
                .unwrap_or_default();
        }
        if network(name) {
            return Flow {
                remote: true,
                steps: vec![format!(
                    "network response at line {}",
                    self.line(call.span.start)
                )],
                ..Default::default()
            };
        }
        if [
            "fs.readFileSync",
            "fs.readFile",
            "fs.promises.readFile",
            "fs.createReadStream",
        ]
        .contains(&name)
            && arguments.first().is_some_and(|a| a.path)
        {
            return Flow {
                secret: true,
                steps: vec![format!(
                    "credential-file read at line {}",
                    self.line(call.span.start)
                )],
                ..Default::default()
            };
        }
        let mut value = Flow::default();
        for a in arguments.iter().cloned() {
            value.merge(a);
        }
        if ["Buffer.from", "atob"].contains(&name) {
            let encoding = if name == "atob" {
                Some("base64")
            } else {
                arguments.get(1).and_then(|a| a.literal.as_deref())
            };
            if let (Some(input), Some(encoding)) = (
                arguments.first().and_then(|a| a.literal.as_deref()),
                encoding,
            ) {
                if ["base64", "hex"].contains(&encoding) {
                    if input.len() > 87384 || value.decoded >= 3 {
                        self.gap("constant_decode_limit");
                        return value;
                    }
                    let decoded = if encoding == "base64" {
                        STANDARD
                            .decode(input)
                            .or_else(|_| STANDARD_NO_PAD.decode(input))
                            .ok()
                    } else {
                        hex::decode(input).ok()
                    };
                    if let Some(bytes) = decoded {
                        if bytes.len() > 65536 {
                            self.gap("constant_decode_limit");
                            return value;
                        }
                        value.literal = String::from_utf8(bytes).ok();
                        value.decoded += 1;
                        value.steps.push(format!(
                            "bounded {encoding} decode at line {}",
                            self.line(call.span.start)
                        ));
                    }
                } else {
                    value.literal = arguments.first().and_then(|a| a.literal.clone());
                }
            }
            return value;
        }
        if let Expression::StaticMemberExpression(member) = call.callee.get_inner_expression()
            && ["toString", "text", "json", "arrayBuffer", "trim"]
                .contains(&member.property.name.as_str())
        {
            return self.value(&member.object, depth);
        }
        if ["JSON.stringify", "JSON.parse", "path.join", "path.resolve"].contains(&name) {
            return value;
        }
        Flow::default()
    }
    fn emit(
        &mut self,
        rule: &str,
        severity: &str,
        position: u32,
        explanation: &str,
        steps: Vec<String>,
    ) {
        self.report.findings.push(Finding {
            rule_id: rule.into(),
            rule_version: "1.0.0".into(),
            severity: severity.into(),
            confidence: if severity == "informational" {
                "high"
            } else {
                "medium"
            }
            .into(),
            file: self.file.into(),
            line: self.line(position),
            explanation: explanation.into(),
            observations: steps,
        });
    }
    fn sinks(&mut self, name: &str, args: Vec<Flow>, position: u32) {
        let mut value = Flow::default();
        for a in args {
            value.merge(a);
        }
        if network(name) && value.secret {
            self.emit("ZOLI-LOCAL-001","high",position,"Credential data may flow into an outbound request; static flow does not prove malicious intent or execution",value.steps.clone());
        }
        if execution(name) && value.remote {
            self.emit(
                "ZOLI-LOCAL-002",
                "high",
                position,
                "Downloaded data may flow into process execution or dynamic evaluation",
                value.steps.clone(),
            );
        }
        if execution(name) && value.decoded > 0 {
            self.emit("ZOLI-LOCAL-003","medium",position,"A decoded constant flows into dynamic execution; review the bounded transform chain",value.steps.clone());
        }
        if matches!(name, "eval" | "Function") && value.decoded == 0 && !value.remote {
            self.emit(
                "ZOLI-LOCAL-102",
                "informational",
                position,
                "Dynamic evaluation is present; this observation alone is not malware",
                vec![],
            );
        }
    }
}
impl<'a> Visit<'a> for Scanner<'_> {
    fn visit_expression(&mut self, e: &Expression<'a>) {
        self.nodes += 1;
        if self.nodes > 1_000_000 {
            self.gap("syntax_node_limit");
            return;
        }
        walk::walk_expression(self, e);
    }
    fn visit_import_declaration(&mut self, it: &ImportDeclaration<'a>) {
        let module = it
            .source
            .value
            .as_str()
            .strip_prefix("node:")
            .unwrap_or(it.source.value.as_str());
        for spec in it.specifiers.iter().flatten() {
            let (id, name) = match spec {
                ImportDeclarationSpecifier::ImportSpecifier(s) => {
                    (&s.local, format!("{module}.{}", s.imported.name()))
                }
                ImportDeclarationSpecifier::ImportDefaultSpecifier(s) => {
                    (&s.local, module.to_owned())
                }
                ImportDeclarationSpecifier::ImportNamespaceSpecifier(s) => {
                    (&s.local, module.to_owned())
                }
            };
            if let Some(id) = id.symbol_id.get() {
                self.values.insert(id, Flow::symbol(&name));
            }
        }
    }
    fn visit_variable_declarator(&mut self, it: &VariableDeclarator<'a>) {
        walk::walk_variable_declarator(self, it);
        if let Some(init) = &it.init {
            let value = self.value(init, 0);
            self.bind(&it.id, value);
        }
    }
    fn visit_assignment_expression(&mut self, it: &AssignmentExpression<'a>) {
        walk::walk_assignment_expression(self, it);
        if let AssignmentTarget::AssignmentTargetIdentifier(id) = &it.left
            && let Some(id) = self.reference(id)
        {
            let value = self.value(&it.right, 0);
            self.values.insert(id, value);
        }
    }
    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        let callee = self.value(&it.callee, 0);
        let arguments = self.arguments(&it.arguments, 0);
        self.sinks(
            callee.symbol.as_deref().unwrap_or_default(),
            arguments,
            it.span.start,
        );
        walk::walk_call_expression(self, it);
    }
    fn visit_new_expression(&mut self, it: &NewExpression<'a>) {
        let callee = self.value(&it.callee, 0);
        let arguments = self.arguments(&it.arguments, 0);
        self.sinks(
            callee.symbol.as_deref().unwrap_or_default(),
            arguments,
            it.span.start,
        );
        walk::walk_new_expression(self, it);
    }
    fn visit_function(&mut self, it: &Function<'a>, flags: ScopeFlags) {
        let previous = self.values.clone();
        walk::walk_function(self, it, flags);
        self.values = previous;
    }
    fn visit_arrow_function_expression(&mut self, it: &ArrowFunctionExpression<'a>) {
        let previous = self.values.clone();
        walk::walk_arrow_function_expression(self, it);
        self.values = previous;
    }
}
