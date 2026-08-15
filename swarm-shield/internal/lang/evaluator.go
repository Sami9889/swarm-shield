package lang

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type ValueType string

const (
	ValueString  ValueType = "string"
	ValueNumber  ValueType = "number"
	ValueBool    ValueType = "bool"
	ValueArray   ValueType = "array"
	ValueNull    ValueType = "null"
	ValueAction  ValueType = "action"
)

type Value struct {
	Type    ValueType
	Text    string
	Number  float64
	Bool    bool
	Array   []Value
	Action  string
}

func (v Value) String() string {
	switch v.Type {
	case ValueString:
		return v.Text
	case ValueNumber:
		return strconv.FormatFloat(v.Number, 'f', -1, 64)
	case ValueBool:
		if v.Bool {
			return "true"
		}
		return "false"
	case ValueArray:
		var parts []string
		for _, el := range v.Array {
			parts = append(parts, el.String())
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case ValueAction:
		return v.Action
	default:
		return "null"
	}
}

type HTTPRequest struct {
	Method     string
	Path      string
	Header    http.Header
	RemoteAddr string
	Query      map[string]string
}

type EventContext struct {
	Request  *HTTPRequest
	EventType string
	Status    int
	DurationMs int64
	APIKey    string
	PeerID    string
	IPAddress string
	Timestamp time.Time
}

type EvaluationResult struct {
	Action  string 
	Message string
	Fields  map[string]Value
}

type Evaluator struct {
	rules   map[string]*RuleDef
	globals map[string]Value
}

func NewEvaluator(rules []Rule) *Evaluator {
	ev := &Evaluator{
		rules:   make(map[string]*RuleDef),
		globals: make(map[string]Value),
	}
	for _, r := range rules {
		if def, ok := r.(*RuleDef); ok {
			key := string(def.RuleType) + ":" + def.Name
			ev.rules[key] = def
		}
	}
	return ev
}

func (e *Evaluator) RuleKeys() []string {
	keys := make([]string, 0, len(e.rules))
	for k := range e.rules {
		keys = append(keys, k)
	}
	return keys
}

func (e *Evaluator) EvaluateRateLimit(name string) (int, int, string) {
	key := string(RuleTypeRateLimit) + ":" + name
	rule, ok := e.rules[key]
	if !ok {
		return 100, 60, "ip"
	}

	limit := 100
	window := 60
	keyType := "ip"

	for _, stmt := range rule.Body {
		if assign, ok := stmt.(*AssignStmt); ok {
			switch assign.Key {
			case "limit":
				if num, ok := assign.Value.(*NumberLiteral); ok {
					limit = int(num.Value)
				}
			case "window":
				if str, ok := assign.Value.(*StringLiteral); ok {
					window = parseDuration(str.Value)
				}
			case "key":
				if str, ok := assign.Value.(*StringLiteral); ok {
					keyType = str.Value
				}
			}
		}
	}

	return limit, window, keyType
}

func (e *Evaluator) EvaluateACL(name string, ctx *EventContext) *EvaluationResult {
	key := string(RuleTypeACL) + ":" + name
	rule, ok := e.rules[key]
	if !ok {
		return &EvaluationResult{Action: "allow"}
	}

	return e.executeBlock(rule.Body, ctx)
}

func (e *Evaluator) EvaluateAuditRule(name string, ctx *EventContext) map[string]Value {
	key := string(RuleTypeAudit) + ":" + name
	rule, ok := e.rules[key]
	if !ok {
		return nil
	}

	result := &EvaluationResult{}
	e.executeBlock(rule.Body, ctx)
	return result.Fields
}

func (e *Evaluator) EvaluateEventHandler(eventName string, ctx *EventContext) {
	key := string(RuleTypeEvent) + ":" + eventName
	rule, ok := e.rules[key]
	if !ok {
		return
	}
	e.executeBlock(rule.Body, ctx)
}

func (e *Evaluator) executeBlock(body []Statement, ctx *EventContext) *EvaluationResult {
	result := &EvaluationResult{Fields: make(map[string]Value)}
	for _, stmt := range body {
		e.execute(stmt, ctx, result)
		if result.Action != "" {
			return result
		}
	}
	return result
}

func (e *Evaluator) execute(stmt Statement, ctx *EventContext, result *EvaluationResult) {
	switch s := stmt.(type) {
	case *IfStmt:
		cond := e.evaluate(s.Condition, ctx)
		if isTruthy(cond) {
			res := e.executeBlock(s.Body, ctx)
			if res.Action != "" {
				result.Action = res.Action
				result.Message = res.Message
				result.Fields = mergeFields(result.Fields, res.Fields)
			}
		} else if len(s.ElseBody) > 0 {
			res := e.executeBlock(s.ElseBody, ctx)
			if res.Action != "" {
				result.Action = res.Action
				result.Message = res.Message
				result.Fields = mergeFields(result.Fields, res.Fields)
			}
		}
	case *AssignStmt:
		val := e.evaluate(s.Value, ctx)
		result.Fields[s.Key] = val
	case *ExprStmt:
		val := e.evaluate(s.Expr, ctx)
		if val.Type == ValueAction {
			result.Action = val.Action
		}
		if val.Type == ValueString {
			result.Message = val.Text
		}
	default:
		_ = stmt.String()
	}
}

func (e *Evaluator) evaluate(expr Expression, ctx *EventContext) Value {
	switch node := expr.(type) {
	case *BinaryExpr:
		return e.evaluateBinary(node, ctx)
	case *UnaryExpr:
		right := e.evaluate(node.Right, ctx)
		if node.Operator == "!" {
			return Value{Type: ValueBool, Bool: !isTruthy(right)}
		}
		return right
	case *CallExpr:
		return e.evaluateCall(node, ctx)
	case *MethodCallExpr:
		return e.evaluateMethodCall(node, ctx)
	case *PropertyAccessExpr:
		obj := e.evaluate(node.Object, ctx)
		switch node.Property {
		case "length":
			return Value{Type: ValueNumber, Number: float64(len(obj.Array))}
		default:
			return Value{Type: ValueNull}
		}
	case *StringLiteral:
		return Value{Type: ValueString, Text: node.Value}
	case *NumberLiteral:
		return Value{Type: ValueNumber, Number: node.Value}
	case *BoolLiteral:
		return Value{Type: ValueBool, Bool: node.Value}
	case *NullLiteral:
		return Value{Type: ValueNull}
	case *IdentExpr:
		if strings.HasPrefix(node.Value, "$") {
			return e.resolveContextVar(node.Value, ctx)
		}
		if node.Value == "allow" {
			return Value{Type: ValueAction, Action: "allow"}
		}
		if node.Value == "deny" {
			return Value{Type: ValueAction, Action: "deny"}
		}
		if v, ok := e.globals[node.Value]; ok {
			return v
		}
		return Value{Type: ValueNull}
	case *ArrayLiteral:
		var elements []Value
		for _, el := range node.Elements {
			elements = append(elements, e.evaluate(el, ctx))
		}
		return Value{Type: ValueArray, Array: elements}
	default:
		return Value{Type: ValueNull}
	}
}

func (e *Evaluator) evaluateBinary(node *BinaryExpr, ctx *EventContext) Value {
	left := e.evaluate(node.Left, ctx)
	right := e.evaluate(node.Right, ctx)

	switch node.Operator {
	case "==":
		return Value{Type: ValueBool, Bool: compareEqual(left, right)}
	case "!=":
		return Value{Type: ValueBool, Bool: !compareEqual(left, right)}
	case ">", "<", ">=", "<=":
		return Value{Type: ValueBool, Bool: compareOrdered(left, right, node.Operator)}
	case "&&":
		return Value{Type: ValueBool, Bool: isTruthy(left) && isTruthy(right)}
	case "||":
		return Value{Type: ValueBool, Bool: isTruthy(left) || isTruthy(right)}
	default:
		return Value{Type: ValueBool, Bool: false}
	}
}

func (e *Evaluator) evaluateCall(node *CallExpr, ctx *EventContext) Value {
	switch node.Callee {
	case "log":
		if len(node.Arguments) > 0 {
			msg := e.evaluate(node.Arguments[0], ctx)
			return Value{Type: ValueString, Text: "log:" + msg.Text}
		}
		return Value{Type: ValueNull}
	case "alert":
		if len(node.Arguments) > 0 {
			msg := e.evaluate(node.Arguments[0], ctx)
			return Value{Type: ValueString, Text: "alert:" + msg.Text}
		}
		return Value{Type: ValueNull}
	case "redact":
		return Value{Type: ValueNull}
	case "allow":
		return Value{Type: ValueAction, Action: "allow"}
	case "deny":
		return Value{Type: ValueAction, Action: "deny"}
	default:
		return Value{Type: ValueNull}
	}
}

func (e *Evaluator) evaluateMethodCall(node *MethodCallExpr, ctx *EventContext) Value {
	obj := e.evaluate(node.Object, ctx)
	if len(node.Arguments) != 1 {
		return Value{Type: ValueBool, Bool: false}
	}
	arg := e.evaluate(node.Arguments[0], ctx)
	pattern := arg.Text

	switch node.Method {
	case "matches":
		matched, _ := regexp.MatchString(pattern, obj.Text)
		return Value{Type: ValueBool, Bool: matched}
	case "starts_with":
		return Value{Type: ValueBool, Bool: strings.HasPrefix(obj.Text, pattern)}
	case "ends_with":
		return Value{Type: ValueBool, Bool: strings.HasSuffix(obj.Text, pattern)}
	case "contains":
		return Value{Type: ValueBool, Bool: strings.Contains(obj.Text, pattern)}
	default:
		return Value{Type: ValueBool, Bool: false}
	}
}

func (e *Evaluator) resolveContextVar(name string, ctx *EventContext) Value {
	if ctx == nil || ctx.Request == nil {
		return Value{Type: ValueNull}
	}

	switch name {
	case "$ip":
		return Value{Type: ValueString, Text: ctx.IPAddress}
	case "$path":
		return Value{Type: ValueString, Text: ctx.Request.Path}
	case "$method":
		return Value{Type: ValueString, Text: ctx.Request.Method}
	case "$status":
		return Value{Type: ValueNumber, Number: float64(ctx.Status)}
	case "$duration":
		return Value{Type: ValueNumber, Number: float64(ctx.DurationMs)}
	case "$event":
		return Value{Type: ValueString, Text: ctx.EventType}
	case "$api_key":
		return Value{Type: ValueString, Text: ctx.APIKey}
	case "$peer_id":
		return Value{Type: ValueString, Text: ctx.PeerID}
	case "$header":
		return Value{Type: ValueNull}
	case "$query":
		return Value{Type: ValueNull}
	default:
		if strings.HasPrefix(name, "$header.") {
			headerName := strings.TrimPrefix(name, "$header.")
			return Value{Type: ValueString, Text: ctx.Request.Header.Get(headerName)}
		}
		if strings.HasPrefix(name, "$query.") {
			queryName := strings.TrimPrefix(name, "$query.")
			if val, ok := ctx.Request.Query[queryName]; ok {
				return Value{Type: ValueString, Text: val}
			}
			return Value{Type: ValueString, Text: ""}
		}
		return Value{Type: ValueNull}
	}
}

func isTruthy(v Value) bool {
	switch v.Type {
	case ValueBool:
		return v.Bool
	case ValueString:
		return v.Text != ""
	case ValueNumber:
		return v.Number != 0
	case ValueAction:
		return v.Action != ""
	default:
		return false
	}
}

func compareEqual(left, right Value) bool {
	if left.Type != right.Type {
		return left.Text == right.Text
	}
	switch left.Type {
	case ValueString:
		return left.Text == right.Text
	case ValueNumber:
		return left.Number == right.Number
	case ValueBool:
		return left.Bool == right.Bool
	case ValueNull:
		return right.Type == ValueNull
	default:
		return false
	}
}

func compareOrdered(left, right Value, op string) bool {
	if left.Type == ValueString && right.Type == ValueString {
		switch op {
		case ">":
			return left.Text > right.Text
		case "<":
			return left.Text < right.Text
		case ">=":
			return left.Text >= right.Text
		case "<=":
			return left.Text <= right.Text
		}
	}

	if left.Type == ValueNumber && right.Type == ValueNumber {
		switch op {
		case ">":
			return left.Number > right.Number
		case "<":
			return left.Number < right.Number
		case ">=":
			return left.Number >= right.Number
		case "<=":
			return left.Number <= right.Number
		}
	}

	if left.Type == ValueNumber && right.Type == ValueString {
		if n, err := strconv.ParseFloat(right.Text, 64); err == nil {
			switch op {
			case ">":
				return left.Number > n
			case "<":
				return left.Number < n
			case ">=":
				return left.Number >= n
			case "<=":
				return left.Number <= n
			}
		}
	}

	return false
}

func mergeFields(a, b map[string]Value) map[string]Value {
	if b == nil {
		return a
	}
	if a == nil {
		return b
	}
	for k, v := range b {
		a[k] = v
	}
	return a
}

func parseDuration(s string) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return 60
	}

	if strings.HasSuffix(s, "s") {
		v, _ := strconv.Atoi(strings.TrimSuffix(s, "s"))
		return v
	}
	if strings.HasSuffix(s, "m") {
		v, _ := strconv.Atoi(strings.TrimSuffix(s, "m"))
		return v * 60
	}
	if strings.HasSuffix(s, "h") {
		v, _ := strconv.Atoi(strings.TrimSuffix(s, "h"))
		return v * 3600
	}
	v, _ := strconv.Atoi(s)
	return v
}
