package engine

import (
	"fmt"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
)

// ApplyFixes edits files with hclwrite, which preserves comments and formatting.
// It returns only the files that changed, plus one error per fix that failed.
func ApplyFixes(files map[string]string, fixes []*Fix) (map[string]string, []error) {
	changed := map[string]string{}
	var errs []error
	for _, fx := range fixes {
		src, ok := changed[fx.File]
		if !ok {
			src, ok = files[fx.File]
		}
		if !ok {
			errs = append(errs, fmt.Errorf("%s: file not found", fx.File))
			continue
		}
		out, err := applyFix(src, fx)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s %s: %w", fx.File, fx.Block, err))
			continue
		}
		changed[fx.File] = out
	}
	return changed, errs
}

func applyFix(src string, fx *Fix) (string, error) {
	f, diags := hclwrite.ParseConfig([]byte(src), fx.File, hcl.InitialPos)
	if diags.HasErrors() {
		return "", fmt.Errorf("cannot parse: %s", diags.Error())
	}
	parts := strings.Split(fx.Block, ".")
	if len(parts) < 2 || len(fx.Path) == 0 {
		return "", fmt.Errorf("invalid fix target")
	}
	blk := f.Body().FirstMatchingBlock(parts[0], parts[1:])
	if blk == nil {
		return "", fmt.Errorf("block not found")
	}
	body := blk.Body()
	for _, name := range fx.Path[:len(fx.Path)-1] {
		nb := body.FirstMatchingBlock(name, nil)
		if nb == nil {
			nb = body.AppendNewBlock(name, nil)
		}
		body = nb.Body()
	}
	var v cty.Value
	switch t := fx.Value.(type) {
	case bool:
		v = cty.BoolVal(t)
	case string:
		v = cty.StringVal(t)
	case int:
		v = cty.NumberIntVal(int64(t))
	case float64:
		v = cty.NumberFloatVal(t)
	default:
		return "", fmt.Errorf("unsupported fix value %T", fx.Value)
	}
	body.SetAttributeValue(fx.Path[len(fx.Path)-1], v)
	return string(f.Bytes()), nil
}
