package lang

import (
	"fmt"
	"strings"
	"unicode"
)

type TokenType int

const (
	TokenEOF TokenType = iota
	TokenIdent
	TokenString
	TokenNumber
	TokenLBrace
	TokenRBrace
	TokenLParen
	TokenRParen
	TokenLBracket
	TokenRBracket
	TokenComma
	TokenColon
	TokenSemicolon
	TokenEq
	TokenNe
	TokenLt
	TokenGt
	TokenLe
	TokenGe
	TokenAnd
	TokenOr
	TokenNot
	TokenComment
	TokenDot
)

type Token struct {
	Type    TokenType
	Literal string
	Line    int
	Column  int
}

func (t Token) String() string {
	return fmt.Sprintf("%s(%q)@%d:%d", tokenNames[t.Type], t.Literal, t.Line, t.Column)
}

var tokenNames = map[TokenType]string{
	TokenEOF:        "EOF",
	TokenIdent:      "IDENT",
	TokenString:     "STRING",
	TokenNumber:     "NUMBER",
	TokenLBrace:     "LBRACE",
	TokenRBrace:     "RBRACE",
	TokenLParen:     "LPAREN",
	TokenRParen:     "RPAREN",
	TokenLBracket:   "LBRACKET",
	TokenRBracket:   "RBRACKET",
	TokenComma:      "COMMA",
	TokenColon:      "COLON",
	TokenSemicolon:  "SEMICOLON",
	TokenEq:         "EQ",
	TokenNe:         "NE",
	TokenLt:         "LT",
	TokenGt:         "GT",
	TokenLe:         "LE",
	TokenGe:         "GE",
	TokenAnd:        "AND",
	TokenOr:         "OR",
	TokenNot:        "NOT",
	TokenComment:    "COMMENT",
	TokenDot:        "DOT",
}

type Lexer struct {
	input   string
	pos     int
	line    int
	column  int
	tokens  []Token
}

func NewLexer(input string) *Lexer {
	return &Lexer{
		input:  input,
		line:   1,
		column: 1,
	}
}

func (l *Lexer) Next() rune {
	if l.pos >= len(l.input) {
		return 0
	}
	ch := rune(l.input[l.pos])
	l.pos++
	if ch == '\n' {
		l.line++
		l.column = 1
	} else {
		l.column++
	}
	return ch
}

func (l *Lexer) Peek() rune {
	if l.pos >= len(l.input) {
		return 0
	}
	return rune(l.input[l.pos])
}

func (l *Lexer) SkipWhitespace() {
	for {
		ch := l.Peek()
		if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' {
			l.Next()
		} else {
			break
		}
	}
}

func (l *Lexer) ReadString(quote rune) (string, error) {
	var sb strings.Builder
	l.Next() 
	for {
		ch := l.Next()
		if ch == 0 {
			return "", fmt.Errorf("unterminated string at line %d, col %d", l.line, l.column)
		}
		if ch == quote {
			break
		}
		if ch == '\\' {
			next := l.Next()
			switch next {
			case 'n':
				sb.WriteRune('\n')
			case 't':
				sb.WriteRune('\t')
			case '\\':
				sb.WriteRune('\\')
			case quote:
				sb.WriteRune(quote)
			default:
				return "", fmt.Errorf("invalid escape sequence at line %d, col %d", l.line, l.column)
			}
		} else {
			sb.WriteRune(ch)
		}
	}
	return sb.String(), nil
}

func (l *Lexer) ReadNumber() string {
	var sb strings.Builder
	for {
		ch := l.Peek()
		if ch >= '0' && ch <= '9' || ch == '.' {
			sb.WriteRune(l.Next())
		} else {
			break
		}
	}
	return sb.String()
}

func (l *Lexer) ReadIdent() string {
	var sb strings.Builder
	for {
		ch := l.Peek()
		if ch == '_' || ch == '$' || unicode.IsLetter(ch) || unicode.IsDigit(ch) {
			sb.WriteRune(l.Next())
		} else {
			break
		}
	}
	return sb.String()
}

func (l *Lexer) ReadComment() string {
	var sb strings.Builder
	for {
		ch := l.Next()
		if ch == '\n' || ch == 0 {
			break
		}
		sb.WriteRune(ch)
	}
	return sb.String()
}

func (l *Lexer) Tokenize() ([]Token, error) {
	var tokens []Token

	for {
		l.SkipWhitespace()
		ch := l.Peek()
		if ch == 0 {
			tokens = append(tokens, Token{Type: TokenEOF, Line: l.line, Column: l.column})
			break
		}

		if ch == '/' && l.pos+1 < len(l.input) && l.input[l.pos+1] == '/' {
			l.Next()
			l.Next()
			_ = l.ReadComment()
			continue
		}

		startLine, startCol := l.line, l.column

		switch ch {
		case '{':
			l.Next()
			tokens = append(tokens, Token{Type: TokenLBrace, Literal: "{", Line: startLine, Column: startCol})
		case '}':
			l.Next()
			tokens = append(tokens, Token{Type: TokenRBrace, Literal: "}", Line: startLine, Column: startCol})
		case '(':
			l.Next()
			tokens = append(tokens, Token{Type: TokenLParen, Literal: "(", Line: startLine, Column: startCol})
		case ')':
			l.Next()
			tokens = append(tokens, Token{Type: TokenRParen, Literal: ")", Line: startLine, Column: startCol})
		case '[':
			l.Next()
			tokens = append(tokens, Token{Type: TokenLBracket, Literal: "[", Line: startLine, Column: startCol})
		case ']':
			l.Next()
			tokens = append(tokens, Token{Type: TokenRBracket, Literal: "]", Line: startLine, Column: startCol})
		case ',':
			l.Next()
			tokens = append(tokens, Token{Type: TokenComma, Literal: ",", Line: startLine, Column: startCol})
		case ':':
			l.Next()
			tokens = append(tokens, Token{Type: TokenColon, Literal: ":", Line: startLine, Column: startCol})
		case ';':
			l.Next()
			tokens = append(tokens, Token{Type: TokenSemicolon, Literal: ";", Line: startLine, Column: startCol})
		case '.':
			l.Next()
			tokens = append(tokens, Token{Type: TokenDot, Literal: ".", Line: startLine, Column: startCol})
		case '=':
			l.Next()
			if l.Peek() == '=' {
				l.Next()
				tokens = append(tokens, Token{Type: TokenEq, Literal: "==", Line: startLine, Column: startCol})
			} else {
				tokens = append(tokens, Token{Type: TokenEq, Literal: "=", Line: startLine, Column: startCol})
			}
		case '!':
			l.Next()
			if l.Peek() == '=' {
				l.Next()
				tokens = append(tokens, Token{Type: TokenNe, Literal: "!=", Line: startLine, Column: startCol})
			} else {
				tokens = append(tokens, Token{Type: TokenNot, Literal: "!", Line: startLine, Column: startCol})
			}
		case '<':
			l.Next()
			if l.Peek() == '=' {
				l.Next()
				tokens = append(tokens, Token{Type: TokenLe, Literal: "<=", Line: startLine, Column: startCol})
			} else {
				tokens = append(tokens, Token{Type: TokenLt, Literal: "<", Line: startLine, Column: startCol})
			}
		case '>':
			l.Next()
			if l.Peek() == '=' {
				l.Next()
				tokens = append(tokens, Token{Type: TokenGe, Literal: ">=", Line: startLine, Column: startCol})
			} else {
				tokens = append(tokens, Token{Type: TokenGt, Literal: ">", Line: startLine, Column: startCol})
			}
		case '&':
			l.Next()
			if l.Peek() == '&' {
				l.Next()
				tokens = append(tokens, Token{Type: TokenAnd, Literal: "&&", Line: startLine, Column: startCol})
			}
		case '|':
			l.Next()
			if l.Peek() == '|' {
				l.Next()
				tokens = append(tokens, Token{Type: TokenOr, Literal: "||", Line: startLine, Column: startCol})
			}
		case '"', '\'':
			str, err := l.ReadString(ch)
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, Token{Type: TokenString, Literal: str, Line: startLine, Column: startCol})
		default:
			if unicode.IsDigit(ch) {
				num := l.ReadNumber()
				tokens = append(tokens, Token{Type: TokenNumber, Literal: num, Line: startLine, Column: startCol})
				continue
			}
			if ch == '_' || ch == '$' || unicode.IsLetter(ch) {
				ident := l.ReadIdent()
				tokType := TokenIdent
				switch ident {
				case "define", "if", "else", "allow", "deny", "log", "alert", "set", "redact", "on", "event", "true", "false", "null":
				}
				tokens = append(tokens, Token{Type: tokType, Literal: ident, Line: startLine, Column: startCol})
				continue
			}
			return nil, fmt.Errorf("unexpected character '%c' at line %d, col %d", ch, l.line, l.column)
		}
	}

	return tokens, nil
}
