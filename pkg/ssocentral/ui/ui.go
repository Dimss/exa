package ui

import (
	"bytes"
	"embed"
	"github.com/Masterminds/sprig"
	"go.uber.org/zap"
	"html/template"
	"io/fs"
)

//go:embed tmpl/assets*
var HtmlAssets embed.FS

//go:embed tmpl/central.html
var htmlCentral embed.FS

type Central struct {
	Name    string
	Color   string
	Title   string
	Headers map[string][]string
}

func NewCentral(title, color string, h map[string][]string) *Central {
	return &Central{
		Name:    "central.html",
		Color:   color,
		Title:   title,
		Headers: h,
	}
}

func (c *Central) Parse() []byte {
	return parse(htmlCentral, c.Name, c)
}

func parse(fs fs.FS, templateName string, data interface{}) []byte {
	var tpl bytes.Buffer
	t, err := template.New(templateName).
		Option("missingkey=error").
		Funcs(sprig.HtmlFuncMap()).
		ParseFS(fs, "tmpl/"+templateName)

	if err != nil {
		zap.S().Error(err)
		return nil
	}

	if err := t.ExecuteTemplate(&tpl, templateName, data); err != nil {
		zap.S().Error(err)
	}
	return tpl.Bytes()
}
