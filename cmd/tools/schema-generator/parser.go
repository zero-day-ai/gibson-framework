package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strings"

	coremodels "github.com/zero-day-ai/gibson-framework/pkg/core/models"
)

const (
	modelsPackagePath = "pkg/core/models/models.go"
	payloadStructName = "PayloadDB"
)

// StructParser handles parsing Go structs using AST
type StructParser struct {
	fileSet *token.FileSet
}

// ParsePayloadDB parses the PayloadDB struct from the models file
func (p *StructParser) ParsePayloadDB() coremodels.Result[StructInfo] {
	p.fileSet = token.NewFileSet()

	// Parse the models file
	node, err := parser.ParseFile(p.fileSet, modelsPackagePath, nil, parser.ParseComments)
	if err != nil {
		return coremodels.Err[StructInfo](fmt.Errorf("failed to parse models file: %w", err))
	}

	// Find the PayloadDB struct
	var payloadStruct *ast.StructType
	var structName string

	ast.Inspect(node, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.TypeSpec:
			if x.Name.Name == payloadStructName {
				if structType, ok := x.Type.(*ast.StructType); ok {
					payloadStruct = structType
					structName = x.Name.Name
					return false
				}
			}
		}
		return true
	})

	if payloadStruct == nil {
		return coremodels.Err[StructInfo](fmt.Errorf("PayloadDB struct not found in %s", modelsPackagePath))
	}

	// Parse struct fields
	fieldsResult := p.parseStructFields(payloadStruct)
	if fieldsResult.IsErr() {
		return coremodels.Err[StructInfo](fmt.Errorf("failed to parse struct fields: %w", fieldsResult.Error()))
	}

	return coremodels.Ok(StructInfo{
		Name:   structName,
		Fields: fieldsResult.Unwrap(),
	})
}

// parseStructFields parses all fields in a struct
func (p *StructParser) parseStructFields(structType *ast.StructType) coremodels.Result[[]FieldInfo] {
	var fields []FieldInfo

	for _, field := range structType.Fields.List {
		// Skip fields without names (embedded fields)
		if len(field.Names) == 0 {
			continue
		}

		for _, name := range field.Names {
			fieldInfo := p.parseField(name, field)
			if fieldInfo.IsErr() {
				return coremodels.Err[[]FieldInfo](fmt.Errorf("failed to parse field %s: %w", name.Name, fieldInfo.Error()))
			}
			fields = append(fields, fieldInfo.Unwrap())
		}
	}

	return coremodels.Ok(fields)
}

// parseField parses a single struct field
func (p *StructParser) parseField(name *ast.Ident, field *ast.Field) coremodels.Result[FieldInfo] {
	fieldInfo := FieldInfo{
		Name: name.Name,
	}

	// Parse type information
	typeResult := p.parseType(field.Type)
	if typeResult.IsErr() {
		return coremodels.Err[FieldInfo](fmt.Errorf("failed to parse type for field %s: %w", name.Name, typeResult.Error()))
	}
	typeInfo := typeResult.Unwrap()

	fieldInfo.Type = typeInfo.TypeName
	fieldInfo.IsPointer = typeInfo.IsPointer
	fieldInfo.IsSlice = typeInfo.IsSlice
	fieldInfo.IsMap = typeInfo.IsMap
	fieldInfo.ElementType = typeInfo.ElementType
	fieldInfo.KeyType = typeInfo.KeyType
	fieldInfo.ValueType = typeInfo.ValueType

	// Parse struct tags
	if field.Tag != nil {
		tagValue := strings.Trim(field.Tag.Value, "`")
		fieldInfo.JSONTag = p.extractTag(tagValue, "json")
		fieldInfo.DBTag = p.extractTag(tagValue, "db")
		fieldInfo.ValidateTag = p.extractTag(tagValue, "validate")
	}

	return coremodels.Ok(fieldInfo)
}

// TypeInfo represents parsed type information
type TypeInfo struct {
	TypeName    string
	IsPointer   bool
	IsSlice     bool
	IsMap       bool
	ElementType string
	KeyType     string
	ValueType   string
}

// parseType parses type information from an AST expression
func (p *StructParser) parseType(expr ast.Expr) coremodels.Result[TypeInfo] {
	switch t := expr.(type) {
	case *ast.Ident:
		// Basic type (string, int, bool, etc.)
		return coremodels.Ok(TypeInfo{
			TypeName: t.Name,
		})

	case *ast.StarExpr:
		// Pointer type (*Type)
		innerResult := p.parseType(t.X)
		if innerResult.IsErr() {
			return coremodels.Err[TypeInfo](innerResult.Error())
		}
		inner := innerResult.Unwrap()
		inner.IsPointer = true
		return coremodels.Ok(inner)

	case *ast.ArrayType:
		// Slice or array type ([]Type)
		elementResult := p.parseType(t.Elt)
		if elementResult.IsErr() {
			return coremodels.Err[TypeInfo](elementResult.Error())
		}
		element := elementResult.Unwrap()

		return coremodels.Ok(TypeInfo{
			TypeName:    fmt.Sprintf("[]%s", element.TypeName),
			IsSlice:     true,
			ElementType: element.TypeName,
		})

	case *ast.MapType:
		// Map type (map[KeyType]ValueType)
		keyResult := p.parseType(t.Key)
		if keyResult.IsErr() {
			return coremodels.Err[TypeInfo](keyResult.Error())
		}
		key := keyResult.Unwrap()

		valueResult := p.parseType(t.Value)
		if valueResult.IsErr() {
			return coremodels.Err[TypeInfo](valueResult.Error())
		}
		value := valueResult.Unwrap()

		return coremodels.Ok(TypeInfo{
			TypeName:  fmt.Sprintf("map[%s]%s", key.TypeName, value.TypeName),
			IsMap:     true,
			KeyType:   key.TypeName,
			ValueType: value.TypeName,
		})

	case *ast.SelectorExpr:
		// Qualified type (package.Type)
		var pkg string
		if ident, ok := t.X.(*ast.Ident); ok {
			pkg = ident.Name
		}
		return coremodels.Ok(TypeInfo{
			TypeName: fmt.Sprintf("%s.%s", pkg, t.Sel.Name),
		})

	case *ast.InterfaceType:
		// Interface type
		if t.Methods.List == nil || len(t.Methods.List) == 0 {
			return coremodels.Ok(TypeInfo{
				TypeName: "interface{}",
			})
		}
		return coremodels.Ok(TypeInfo{
			TypeName: "interface",
		})

	default:
		// Unknown type, try to get string representation
		return coremodels.Ok(TypeInfo{
			TypeName: fmt.Sprintf("%T", t),
		})
	}
}

// extractTag extracts a specific tag value from struct tag string
func (p *StructParser) extractTag(tagString, tagName string) string {
	// Parse the tag using reflection
	tag := reflect.StructTag(tagString)
	return tag.Get(tagName)
}