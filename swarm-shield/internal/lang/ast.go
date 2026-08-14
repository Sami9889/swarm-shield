package lang

import (
	"fmt"
	"strings"
)

type Node interface {
	String() string
}

type Program struct {
	Rules []Rule
}

func (p *Program) String() string {
	var sb strings.Builder
	for _, r := range p.Rules {
		sb.WriteString(r.String())
		sb.WriteString("\n")
	}
	return sb.String()
}

type Rule interface {
	Node
	ruleNode()
}

type RuleType string

const (
	RuleTypeRateLimit RuleType = "rate_limit"
	RuleTypeACL       RuleType = "acl"
	RuleTypeAudit     RuleType = "audit_rule"
	RuleTypeEvent     RuleType = "event_handler"
)

type RuleDef struct {
	RuleType RuleType
	Name     string
	Body     []Statement
}

func (r *RuleDef) ruleNode() {}
func (r *RuleDef) String() string {
	var sb strings.Builder
	sb.WriteString(string(r.RuleType))
	sb.WriteString(" ")
	sb.WriteString(r.Name)
	sb.WriteString(" {\n")
	for _, s := range r.Body {
		sb.WriteString("  ")
		sb.WriteString(s.String())
		sb.WriteString("\n")
	}
	sb.WriteString("}")
	return sb.String()
}

type Statement interface {
	Node
	statementNode()
}

type ExprStmt struct {
	Expr Expression
}

func (e *ExprStmt) statementNode() {}
func (e *ExprStmt) String() string  { return e.Expr.String() }

type IfStmt struct {
	Condition Expression
	Body      []Statement
	ElseBody  []Statement
}

func (i *IfStmt) statementNode() {}
func (i *IfStmt) String() string {
	var sb strings.Builder
	sb.WriteString("if ")
	sb.WriteString(i.Condition.String())
	sb.WriteString(" {\n")
	for _, s := range i.Body {
		sb.WriteString("  ")
		sb.WriteString(s.String())
		sb.WriteString("\n")
	}
	sb.WriteString("}")
	if len(i.ElseBody) > 0 {
		sb.WriteString(" else {\n")
		for _, s := range i.ElseBody {
			sb.WriteString("  ")
			sb.WriteString(s.String())
			sb.WriteString("\n")
		}
		sb.WriteString("}")
	}
	return sb.String()
}

type AssignStmt struct {
	Key   string
	Value Expression
}

func (a *AssignStmt) statementNode() {}
func (a *AssignStmt) String() string {
	var sb strings.Builder
	sb.WriteString("set ")
	sb.WriteString(a.Key)
	sb.WriteString(" = ")
	sb.WriteString(a.Value.String())
	sb.WriteString(";")
	return sb.String()
}

type Expression interface {
	Node
	expressionNode()
}

type BinaryExpr struct {
	Left     Expression
	Operator string
	Right    Expression
}

func (b *BinaryExpr) expressionNode() {}
func (b *BinaryExpr) String() string {
	var sb strings.Builder
	sb.WriteString("(")
	sb.WriteString(b.Left.String())
	sb.WriteString(" ")
	sb.WriteString(b.Operator)
	sb.WriteString(" ")
	sb.WriteString(b.Right.String())
	sb.WriteString(")")
	return sb.String()
}

type UnaryExpr struct {
	Operator string
	Right    Expression
}

func (u *UnaryExpr) expressionNode() {}
func (u *UnaryExpr) String() string {
	var sb strings.Builder
	sb.WriteString(u.Operator)
	sb.WriteString(" ")
	sb.WriteString(u.Right.String())
	return sb.String()
}

type IdentExpr struct {
	Value string
}

func (i *IdentExpr) expressionNode() {}
func (i *IdentExpr) String() string  { return i.Value }

type StringLiteral struct {
	Value string
}

func (s *StringLiteral) expressionNode() {}
func (s *StringLiteral) String() string  { return fmt.Sprintf("\"%s\"", s.Value) }

type NumberLiteral struct {
	Value float64
}

func (n *NumberLiteral) expressionNode() {}
func (n *NumberLiteral) String() string  { return fmt.Sprintf("%g", n.Value) }

type BoolLiteral struct {
	Value bool
}

func (b *BoolLiteral) expressionNode() {}
func (b *BoolLiteral) String() string {
	if b.Value {
		return "true"
	}
	return "false"
}

type NullLiteral struct{}

func (n *NullLiteral) expressionNode() {}
func (n *NullLiteral) String() string  { return "null" }

type CallExpr struct {
	Callee    string
	Arguments []Expression
}

func (c *CallExpr) expressionNode() {}
func (c *CallExpr) String() string {
	var sb strings.Builder
	sb.WriteString(c.Callee)
	sb.WriteString("(")
	for i, arg := range c.Arguments {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(arg.String())
	}
	sb.WriteString(")")
	return sb.String()
}

type MethodCallExpr struct {
	Object    Expression
	Method    string
	Arguments []Expression
}

func (m *MethodCallExpr) expressionNode() {}
func (m *MethodCallExpr) String() string {
	var sb strings.Builder
	sb.WriteString(m.Object.String())
	sb.WriteString(".")
	sb.WriteString(m.Method)
	sb.WriteString("(")
	for i, arg := range m.Arguments {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(arg.String())
	}
	sb.WriteString(")")
	return sb.String()
}

type PropertyAccessExpr struct {
	Object Expression
	Property string
}

func (p *PropertyAccessExpr) expressionNode() {}
func (p *PropertyAccessExpr) String() string {
	return p.Object.String() + "." + p.Property
}

type ArrayLiteral struct {
	Elements []Expression
}

func (a *ArrayLiteral) expressionNode() {}
func (a *ArrayLiteral) String() string {
	var sb strings.Builder
	sb.WriteString("[")
	for i, el := range a.Elements {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(el.String())
	}
	sb.WriteString("]")
	return sb.String()
}
