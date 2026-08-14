package lang

import (
	"fmt"
	"strconv"
	"strings"
)

type Parser struct {
	tokens  []Token
	pos     int
	Current Token
}

func NewParser(tokens []Token) *Parser {
	p := &Parser{tokens: tokens}
	p.Current = p.tokens[p.pos]
	return p
}

func (p *Parser) advance() {
	p.pos++
	if p.pos < len(p.tokens) {
		p.Current = p.tokens[p.pos]
	} else {
		p.Current = Token{Type: TokenEOF, Line: p.Current.Line, Column: p.Current.Column}
	}
}

func (p *Parser) expect(typ TokenType) error {
	if p.Current.Type != typ {
		return fmt.Errorf("expected %s at line %d, col %d, got %s", tokenNames[typ], p.Current.Line, p.Current.Column, tokenNames[p.Current.Type])
	}
	p.advance()
	return nil
}

func (p *Parser) match(types ...TokenType) bool {
	for _, t := range types {
		if p.Current.Type == t {
			return true
		}
	}
	return false
}

func (p *Parser) Parse() (*Program, error) {
	program := &Program{}
	for p.Current.Type != TokenEOF {
		rule, err := p.parseRule()
		if err != nil {
			return nil, err
		}
		if rule != nil {
			program.Rules = append(program.Rules, rule)
		}
	}
	return program, nil
}

func (p *Parser) parseRule() (Rule, error) {
	if p.match(TokenIdent) && p.Current.Literal == "define" {
		p.advance()
		return p.parseDefine()
	}
	if p.match(TokenIdent) && p.Current.Literal == "on" {
		p.advance()
		return p.parseEventHandler()
	}
	return nil, fmt.Errorf("unexpected token %s at line %d, col %d", tokenNames[p.Current.Type], p.Current.Line, p.Current.Column)
}

func (p *Parser) parseDefine() (Rule, error) {
	if !p.match(TokenIdent) {
		return nil, fmt.Errorf("expected rule type at line %d, col %d", p.Current.Line, p.Current.Column)
	}
	ruleType := RuleType(p.Current.Literal)
	p.advance()

	if p.Current.Type != TokenString {
		return nil, fmt.Errorf("expected rule name string at line %d, col %d", p.Current.Line, p.Current.Column)
	}
	name := p.Current.Literal
	p.advance()

	if err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	var body []Statement
	for !p.match(TokenRBrace) && p.Current.Type != TokenEOF {
		stmt, err := p.parseStatement()
		if err != nil {
			return nil, err
		}
		body = append(body, stmt)
	}

	if err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	return &RuleDef{
		RuleType: ruleType,
		Name:     name,
		Body:     body,
	}, nil
}

func (p *Parser) parseEventHandler() (Rule, error) {
	if p.Current.Literal != "event" {
		return nil, fmt.Errorf("expected 'event' keyword at line %d, col %d", p.Current.Line, p.Current.Column)
	}
	p.advance()

	if p.Current.Type != TokenString {
		return nil, fmt.Errorf("expected event name string at line %d, col %d", p.Current.Line, p.Current.Column)
	}
	eventName := p.Current.Literal
	p.advance()

	if err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	var body []Statement
	for !p.match(TokenRBrace) && p.Current.Type != TokenEOF {
		stmt, err := p.parseStatement()
		if err != nil {
			return nil, err
		}
		body = append(body, stmt)
	}

	if err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	rule := &RuleDef{
		RuleType: RuleTypeEvent,
		Name:     eventName,
		Body:     body,
	}
	return rule, nil
}

func (p *Parser) parseStatement() (Statement, error) {
	if p.match(TokenIdent) && p.Current.Literal == "if" {
		p.advance()
		return p.parseIfStmt()
	}
	if p.match(TokenIdent) && p.Current.Literal == "allow" {
		p.advance()
		return &ExprStmt{Expr: &IdentExpr{Value: "allow"}}, nil
	}
	if p.match(TokenIdent) && p.Current.Literal == "deny" {
		p.advance()
		return &ExprStmt{Expr: &IdentExpr{Value: "deny"}}, nil
	}
	if p.match(TokenIdent) && p.Current.Literal == "log" {
		p.advance()
		return p.parseLogStmt()
	}
	if p.match(TokenIdent) && p.Current.Literal == "alert" {
		p.advance()
		return p.parseAlertStmt()
	}
	if p.match(TokenIdent) && p.Current.Literal == "set" {
		p.advance()
		return p.parseAssignStmt()
	}
	if p.match(TokenIdent) {
		// Try bare assignment: key = value
		pos := p.pos
		ident := p.Current.Literal
		p.advance()
		if p.match(TokenEq) {
			p.advance()
			val, err := p.parseExpression()
			if err == nil {
				return &AssignStmt{Key: ident, Value: val}, nil
			}
		}
		// Not an assignment, backtrack
		p.pos = pos
		p.Current = p.tokens[p.pos]
	}
	if p.match(TokenIdent) && p.Current.Literal == "redact" {
		p.advance()
		return p.parseRedactStmt()
	}

	expr, err := p.parseExpression()
	if err != nil {
		return nil, err
	}
	return &ExprStmt{Expr: expr}, nil
}

func (p *Parser) parseIfStmt() (*IfStmt, error) {
	cond, err := p.parseExpression()
	if err != nil {
		return nil, err
	}

	if err := p.expect(TokenLBrace); err != nil {
		return nil, err
	}

	var body []Statement
	for !p.match(TokenRBrace) && p.Current.Type != TokenEOF {
		stmt, err := p.parseStatement()
		if err != nil {
			return nil, err
		}
		body = append(body, stmt)
	}

	if err := p.expect(TokenRBrace); err != nil {
		return nil, err
	}

	var elseBody []Statement
	if p.match(TokenIdent) && p.Current.Literal == "else" {
		p.advance()
		if err := p.expect(TokenLBrace); err != nil {
			return nil, err
		}
		for !p.match(TokenRBrace) && p.Current.Type != TokenEOF {
			stmt, err := p.parseStatement()
			if err != nil {
				return nil, err
			}
			elseBody = append(elseBody, stmt)
		}
		if err := p.expect(TokenRBrace); err != nil {
			return nil, err
		}
	}

	return &IfStmt{Condition: cond, Body: body, ElseBody: elseBody}, nil
}

func (p *Parser) parseLogStmt() (Statement, error) {
	if p.Current.Type != TokenString {
		return nil, fmt.Errorf("expected string message for log at line %d, col %d", p.Current.Line, p.Current.Column)
	}
	msg := p.Current.Literal
	p.advance()
	return &ExprStmt{Expr: &CallExpr{Callee: "log", Arguments: []Expression{&StringLiteral{Value: msg}}}}, nil
}

func (p *Parser) parseAlertStmt() (Statement, error) {
	if p.Current.Type != TokenString {
		return nil, fmt.Errorf("expected string name for alert at line %d, col %d", p.Current.Line, p.Current.Column)
	}
	name := p.Current.Literal
	p.advance()
	return &ExprStmt{Expr: &CallExpr{Callee: "alert", Arguments: []Expression{&StringLiteral{Value: name}}}}, nil
}

func (p *Parser) parseAssignStmt() (*AssignStmt, error) {
	if p.Current.Type != TokenIdent {
		return nil, fmt.Errorf("expected variable name at line %d, col %d", p.Current.Line, p.Current.Column)
	}
	key := p.Current.Literal
	p.advance()

	if err := p.expect(TokenEq); err != nil {
		return nil, err
	}

	val, err := p.parseExpression()
	if err != nil {
		return nil, err
	}

	return &AssignStmt{Key: key, Value: val}, nil
}

func (p *Parser) parseRedactStmt() (Statement, error) {
	if p.Current.Type != TokenLBracket {
		return nil, fmt.Errorf("expected '[' for redact fields at line %d, col %d", p.Current.Line, p.Current.Column)
	}
	p.advance()

	var fields []string
	for p.Current.Type != TokenRBracket && p.Current.Type != TokenEOF {
		if p.Current.Type != TokenString {
			return nil, fmt.Errorf("expected string field name at line %d, col %d", p.Current.Line, p.Current.Column)
		}
		fields = append(fields, p.Current.Literal)
		p.advance()
		if p.match(TokenComma) {
			p.advance()
		}
	}

	if err := p.expect(TokenRBracket); err != nil {
		return nil, err
	}

	arr := &ArrayLiteral{}
	for _, f := range fields {
		arr.Elements = append(arr.Elements, &StringLiteral{Value: f})
	}
	return &ExprStmt{Expr: &CallExpr{Callee: "redact", Arguments: []Expression{arr}}}, nil
}

func (p *Parser) parseExpression() (Expression, error) {
	return p.parseOr()
}

func (p *Parser) parseOr() (Expression, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.match(TokenOr) {
		p.advance()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &BinaryExpr{Left: left, Operator: "||", Right: right}
	}
	return left, nil
}

func (p *Parser) parseAnd() (Expression, error) {
	left, err := p.parseEquality()
	if err != nil {
		return nil, err
	}
	for p.match(TokenAnd) {
		p.advance()
		right, err := p.parseEquality()
		if err != nil {
			return nil, err
		}
		left = &BinaryExpr{Left: left, Operator: "&&", Right: right}
	}
	return left, nil
}

func (p *Parser) parseEquality() (Expression, error) {
	left, err := p.parseComparison()
	if err != nil {
		return nil, err
	}
	for p.match(TokenEq, TokenNe) {
		op := p.Current.Literal
		p.advance()
		right, err := p.parseComparison()
		if err != nil {
			return nil, err
		}
		left = &BinaryExpr{Left: left, Operator: op, Right: right}
	}
	return left, nil
}

func (p *Parser) parseComparison() (Expression, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for p.match(TokenLt, TokenGt, TokenLe, TokenGe) {
		op := p.Current.Literal
		p.advance()
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = &BinaryExpr{Left: left, Operator: op, Right: right}
	}
	return left, nil
}

func (p *Parser) parseUnary() (Expression, error) {
	if p.match(TokenNot) {
		p.advance()
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return &UnaryExpr{Operator: "!", Right: right}, nil
	}
	return p.parsePostfix()
}

func (p *Parser) parsePostfix() (Expression, error) {
	expr, err := p.parsePrimary()
	if err != nil {
		return nil, err
	}

	for {
		if p.match(TokenIdent) && (p.Current.Literal == "matches" || p.Current.Literal == "starts_with" || p.Current.Literal == "ends_with" || p.Current.Literal == "contains") {
			method := p.Current.Literal
			p.advance()
			arg, err := p.parseExpression()
			if err != nil {
				return nil, err
			}
			expr = &MethodCallExpr{Object: expr, Method: method, Arguments: []Expression{arg}}
		} else if p.match(TokenDot) {
			p.advance()
			if !p.match(TokenIdent) {
				return nil, fmt.Errorf("expected property name after '.' at line %d, col %d", p.Current.Line, p.Current.Column)
			}
			prop := p.Current.Literal
			p.advance()
			expr = &PropertyAccessExpr{Object: expr, Property: prop}
		} else {
			break
		}
	}

	return expr, nil
}

func (p *Parser) parsePrimary() (Expression, error) {
	switch p.Current.Type {
	case TokenIdent:
		val := p.Current.Literal
		p.advance()
		if val == "true" {
			return &BoolLiteral{Value: true}, nil
		}
		if val == "false" {
			return &BoolLiteral{Value: false}, nil
		}
		if val == "null" {
			return &NullLiteral{}, nil
		}

		if p.match(TokenLParen) {
			p.advance()
			var args []Expression
			for !p.match(TokenRParen) && p.Current.Type != TokenEOF {
				arg, err := p.parseExpression()
				if err != nil {
					return nil, err
				}
				args = append(args, arg)
				if p.match(TokenComma) {
					p.advance()
				}
			}
			if err := p.expect(TokenRParen); err != nil {
				return nil, err
			}
			return &CallExpr{Callee: val, Arguments: args}, nil
		}

		return &IdentExpr{Value: val}, nil

	case TokenString:
		val := p.Current.Literal
		p.advance()
		return &StringLiteral{Value: val}, nil

	case TokenNumber:
		numStr := p.Current.Literal
		p.advance()
		if strings.Contains(numStr, ".") {
			val, err := strconv.ParseFloat(numStr, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid number at line %d, col %d", p.Current.Line, p.Current.Column)
			}
			return &NumberLiteral{Value: val}, nil
		}
		val, err := strconv.ParseFloat(numStr, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid number at line %d, col %d", p.Current.Line, p.Current.Column)
		}
		return &NumberLiteral{Value: val}, nil

	case TokenLParen:
		p.advance()
		expr, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		if err := p.expect(TokenRParen); err != nil {
			return nil, err
		}
		return expr, nil

	case TokenLBracket:
		p.advance()
		var elements []Expression
		for !p.match(TokenRBracket) && p.Current.Type != TokenEOF {
			el, err := p.parseExpression()
			if err != nil {
				return nil, err
			}
			elements = append(elements, el)
			if p.match(TokenComma) {
				p.advance()
			}
		}
		if err := p.expect(TokenRBracket); err != nil {
			return nil, err
		}
		return &ArrayLiteral{Elements: elements}, nil

	default:
		return nil, fmt.Errorf("unexpected token %s at line %d, col %d", tokenNames[p.Current.Type], p.Current.Line, p.Current.Column)
	}
}
