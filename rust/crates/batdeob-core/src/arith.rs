//! `set /a` arithmetic evaluator. A Pratt parser over cmd.exe's
//! integer expression grammar with i32 wrapping arithmetic.
//!
//! Operators by precedence (low to high):
//! - `,`               expression sequencing
//! - `= *= /= %= += -= &= ^= |= <<= >>=`   compound assignment
//! - `|`               bitwise or
//! - `^`               bitwise xor
//! - `&`               bitwise and
//! - `<< >>`           shifts
//! - `+ -`             add/subtract
//! - `* / %`           mul/div/mod
//! - unary `! ~ -`     logical-not / bitwise-not / negate
//! - primary           int literal, bare identifier, `( … )`

use crate::env::Environment;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    Int(i64),
    Ident(String),
    Op(Op),
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Comma,
    Assign,
    MulEq,
    DivEq,
    ModEq,
    PlusEq,
    MinusEq,
    AndEq,
    XorEq,
    OrEq,
    ShlEq,
    ShrEq,
    Or,
    Xor,
    And,
    Shl,
    Shr,
    Plus,
    Minus,
    Mul,
    Div,
    Mod,
    Not,
    BitNot,
    Neg,
    LParen,
    RParen,
}

#[derive(Debug)]
#[non_exhaustive]
pub enum EvalError {
    #[allow(dead_code)]
    Parse(String),
}

/// Evaluate a set /a expression. Returns the value of the last sub-expression.
pub fn eval(expr: &str, env: &mut Environment) -> Result<i64, EvalError> {
    let tokens = tokenize(expr)?;
    let mut p = Parser { tokens, pos: 0 };
    let v = p.parse_comma(env)?;
    if p.pos != p.tokens.len() {
        return Err(EvalError::Parse(format!(
            "trailing tokens at pos {}",
            p.pos
        )));
    }
    Ok(v)
}

fn tokenize(s: &str) -> Result<Vec<Token>, EvalError> {
    let mut out = Vec::new();
    let bytes: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c.is_ascii_digit() {
            // Hex (0x), octal (leading 0), or decimal
            let mut j = i;
            let mut radix = 10u32;
            if c == '0'
                && bytes
                    .get(i + 1)
                    .copied()
                    .map(|x| x == 'x' || x == 'X')
                    .unwrap_or(false)
            {
                radix = 16;
                j = i + 2;
                while j < bytes.len() && bytes[j].is_ascii_hexdigit() {
                    j += 1;
                }
            } else if c == '0'
                && bytes
                    .get(i + 1)
                    .copied()
                    .map(|x| x.is_ascii_digit())
                    .unwrap_or(false)
            {
                radix = 8;
                while j < bytes.len() && bytes[j].is_ascii_digit() {
                    j += 1;
                }
            } else {
                while j < bytes.len() && bytes[j].is_ascii_digit() {
                    j += 1;
                }
            }
            let numstr: String = if radix == 16 {
                bytes[i + 2..j].iter().collect()
            } else {
                bytes[i..j].iter().collect()
            };
            // Real CMD's `set /a` parses hex/octal with low-32-bit
            // truncation on overflow — `0x6b84031624 >> 4` evaluates
            // even though the literal doesn't fit in i32/u32. xeno-class
            // goto-bytecode obfuscators rely on this: each label
            // computes a large literal, shifts/masks it, and uses the
            // result as a goto target. Without truncation we error out,
            // `%ans%` empty-expands, the dynamic `goto %ans%` loops on
            // the prior label, and the URL assembly is never reached.
            // Real CMD's `set /a` is 32-bit. Literals > u32::MAX trigger
            // a parse error and the assignment is SKIPPED (the variable
            // keeps its prior value). xeno-class goto-bytecode relies on
            // this: lines with oversized hex (`0x6b84031624`) are
            // intentional decoys that preserve the previously-computed
            // `ans` (a valid label target). My earlier i64-promotion +
            // wrap overwrote `ans` with garbage and broke the chain.
            // Parse strictly as i32 (signed) or u32 (then wrap to i32);
            // error otherwise.
            let n = i32::from_str_radix(&numstr, radix)
                .or_else(|_| u32::from_str_radix(&numstr, radix).map(|u| u as i32))
                .map_err(|_| EvalError::Parse(format!("bad int literal {numstr:?}")))?;
            out.push(Token::Int(n as i64));
            i = j;
            continue;
        }
        if c.is_alphabetic() || c == '_' {
            let mut j = i;
            while j < bytes.len() && (bytes[j].is_alphanumeric() || bytes[j] == '_') {
                j += 1;
            }
            let id: String = bytes[i..j].iter().collect();
            out.push(Token::Ident(id));
            i = j;
            continue;
        }
        // Try 3-char compound shift operators first (must beat 2-char)
        if i + 2 < bytes.len() {
            let trip: String = bytes[i..i + 3].iter().collect();
            if trip == "<<=" {
                out.push(Token::Op(Op::ShlEq));
                i += 3;
                continue;
            }
            if trip == ">>=" {
                out.push(Token::Op(Op::ShrEq));
                i += 3;
                continue;
            }
        }
        // 2-char operators
        let pair = if i + 1 < bytes.len() {
            format!("{}{}", c, bytes[i + 1])
        } else {
            String::new()
        };
        let op_match: Option<(Op, usize)> = match pair.as_str() {
            "<<" => Some((Op::Shl, 2)),
            ">>" => Some((Op::Shr, 2)),
            "+=" => Some((Op::PlusEq, 2)),
            "-=" => Some((Op::MinusEq, 2)),
            "*=" => Some((Op::MulEq, 2)),
            "/=" => Some((Op::DivEq, 2)),
            "%=" => Some((Op::ModEq, 2)),
            "&=" => Some((Op::AndEq, 2)),
            "^=" => Some((Op::XorEq, 2)),
            "|=" => Some((Op::OrEq, 2)),
            _ => match c {
                '=' => Some((Op::Assign, 1)),
                '+' => Some((Op::Plus, 1)),
                '-' => Some((Op::Minus, 1)),
                '*' => Some((Op::Mul, 1)),
                '/' => Some((Op::Div, 1)),
                '%' => Some((Op::Mod, 1)),
                '&' => Some((Op::And, 1)),
                '^' => Some((Op::Xor, 1)),
                '|' => Some((Op::Or, 1)),
                '~' => Some((Op::BitNot, 1)),
                '!' => Some((Op::Not, 1)),
                '(' => Some((Op::LParen, 1)),
                ')' => Some((Op::RParen, 1)),
                ',' => Some((Op::Comma, 1)),
                _ => None,
            },
        };
        match op_match {
            Some((op, n)) => {
                out.push(Token::Op(op));
                i += n;
            }
            None => {
                return Err(EvalError::Parse(format!(
                    "unexpected char {:?} at {}",
                    c, i
                )));
            }
        }
    }
    Ok(out)
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }
    fn advance(&mut self) -> Option<&Token> {
        let t = self.tokens.get(self.pos);
        if t.is_some() {
            self.pos += 1;
        }
        t
    }
    fn check_op(&self, op: Op) -> bool {
        matches!(self.peek(), Some(Token::Op(o)) if *o == op)
    }
    fn eat_op(&mut self, op: Op) -> bool {
        if self.check_op(op) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    fn parse_comma(&mut self, env: &mut Environment) -> Result<i64, EvalError> {
        let mut v = self.parse_assign(env)?;
        while self.eat_op(Op::Comma) {
            v = self.parse_assign(env)?;
        }
        Ok(v)
    }

    fn parse_assign(&mut self, env: &mut Environment) -> Result<i64, EvalError> {
        // Right-associative compound assignment: an identifier followed by an assignment-op
        let save = self.pos;
        if let Some(Token::Ident(name)) = self.peek().cloned() {
            // Peek-ahead: is the next token an assignment op?
            let op = self.tokens.get(self.pos + 1).and_then(|t| match t {
                Token::Op(o) => Some(*o),
                _ => None,
            });
            if let Some(o) = op {
                if matches!(
                    o,
                    Op::Assign
                        | Op::MulEq
                        | Op::DivEq
                        | Op::ModEq
                        | Op::PlusEq
                        | Op::MinusEq
                        | Op::AndEq
                        | Op::XorEq
                        | Op::OrEq
                        | Op::ShlEq
                        | Op::ShrEq
                ) {
                    self.pos += 2;
                    let rhs = self.parse_assign(env)?;
                    let cur = lookup(env, &name);
                    let new = match o {
                        Op::Assign => rhs,
                        Op::MulEq => cur.wrapping_mul(rhs),
                        Op::DivEq => {
                            if rhs == 0 {
                                0
                            } else {
                                cur.wrapping_div(rhs)
                            }
                        }
                        Op::ModEq => {
                            if rhs == 0 {
                                0
                            } else {
                                cur.wrapping_rem(rhs)
                            }
                        }
                        Op::PlusEq => cur.wrapping_add(rhs),
                        Op::MinusEq => cur.wrapping_sub(rhs),
                        Op::AndEq => cur & rhs,
                        Op::XorEq => cur ^ rhs,
                        Op::OrEq => cur | rhs,
                        Op::ShlEq => cur.wrapping_shl(rhs as u32),
                        Op::ShrEq => cur.wrapping_shr(rhs as u32),
                        _ => unreachable!(),
                    };
                    // CMD's `set /a` stores the result as the i32-wrapped
                    // textual repr — never the full i64. So `goto %ans%`
                    // sees the wrapped value. This is the FINAL truncation
                    // point; intermediates above stayed in i64 for shift
                    // precision.
                    env.set(&name, &(new as i32).to_string());
                    return Ok(new);
                }
            }
        }
        self.pos = save;
        self.parse_or(env)
    }

    fn parse_or(&mut self, env: &mut Environment) -> Result<i64, EvalError> {
        let mut v = self.parse_xor(env)?;
        while self.eat_op(Op::Or) {
            let r = self.parse_xor(env)?;
            v |= r;
        }
        Ok(v)
    }
    fn parse_xor(&mut self, env: &mut Environment) -> Result<i64, EvalError> {
        let mut v = self.parse_and(env)?;
        while self.eat_op(Op::Xor) {
            let r = self.parse_and(env)?;
            v ^= r;
        }
        Ok(v)
    }
    fn parse_and(&mut self, env: &mut Environment) -> Result<i64, EvalError> {
        let mut v = self.parse_shift(env)?;
        while self.eat_op(Op::And) {
            let r = self.parse_shift(env)?;
            v &= r;
        }
        Ok(v)
    }
    fn parse_shift(&mut self, env: &mut Environment) -> Result<i64, EvalError> {
        let mut v = self.parse_add(env)?;
        loop {
            if self.eat_op(Op::Shl) {
                let r = self.parse_add(env)?;
                v = v.wrapping_shl(r as u32);
            } else if self.eat_op(Op::Shr) {
                let r = self.parse_add(env)?;
                v = v.wrapping_shr(r as u32);
            } else {
                break;
            }
        }
        Ok(v)
    }
    fn parse_add(&mut self, env: &mut Environment) -> Result<i64, EvalError> {
        let mut v = self.parse_mul(env)?;
        loop {
            if self.eat_op(Op::Plus) {
                let r = self.parse_mul(env)?;
                v = v.wrapping_add(r);
            } else if self.eat_op(Op::Minus) {
                let r = self.parse_mul(env)?;
                v = v.wrapping_sub(r);
            } else {
                break;
            }
        }
        Ok(v)
    }
    fn parse_mul(&mut self, env: &mut Environment) -> Result<i64, EvalError> {
        let mut v = self.parse_unary(env)?;
        loop {
            if self.eat_op(Op::Mul) {
                let r = self.parse_unary(env)?;
                v = v.wrapping_mul(r);
            } else if self.eat_op(Op::Div) {
                let r = self.parse_unary(env)?;
                v = if r == 0 { 0 } else { v.wrapping_div(r) };
            } else if self.eat_op(Op::Mod) {
                let r = self.parse_unary(env)?;
                v = if r == 0 { 0 } else { v.wrapping_rem(r) };
            } else {
                break;
            }
        }
        Ok(v)
    }
    fn parse_unary(&mut self, env: &mut Environment) -> Result<i64, EvalError> {
        if self.eat_op(Op::Minus) {
            let v = self.parse_unary(env)?;
            return Ok(v.wrapping_neg());
        }
        if self.eat_op(Op::Plus) {
            return self.parse_unary(env);
        }
        if self.eat_op(Op::Not) {
            let v = self.parse_unary(env)?;
            return Ok(if v == 0 { 1 } else { 0 });
        }
        if self.eat_op(Op::BitNot) {
            let v = self.parse_unary(env)?;
            return Ok(!v);
        }
        self.parse_primary(env)
    }
    fn parse_primary(&mut self, env: &mut Environment) -> Result<i64, EvalError> {
        if self.eat_op(Op::LParen) {
            let v = self.parse_comma(env)?;
            if !self.eat_op(Op::RParen) {
                return Err(EvalError::Parse("expected )".into()));
            }
            return Ok(v);
        }
        match self.advance().cloned() {
            Some(Token::Int(n)) => Ok(n),
            Some(Token::Ident(name)) => Ok(lookup(env, &name)),
            other => Err(EvalError::Parse(format!(
                "expected primary, got {:?}",
                other
            ))),
        }
    }
}

fn lookup(env: &Environment, name: &str) -> i64 {
    // Looked-up var values are CMD-side strings — they're stored as the
    // user wrote them (i32 textual repr for ans/etc). Parse as i64 so
    // arith chains preserve full precision through shifts/mul.
    env.get(name)
        .and_then(|s| s.trim().parse::<i64>().ok())
        .unwrap_or(0)
}
