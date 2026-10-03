// 批量 parse 探针（Go net/mail）：目录 -> 每文件一行 JSON。
// 与 parse.go 同口径，仅加 case 定位键与 field_count 维度，供 gramfuzz
// stage-1 批量差分。比较元组 (received_count, from_in_headers, field_count)，
// field_count 为 Header map 键数 = 去重（canonical MIME）字段名数。
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/mail"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func main() {
	files, _ := filepath.Glob(filepath.Join(os.Args[1], "*.eml"))
	sort.Strings(files) // Glob 单层模式本身有序；显式排序保险
	for _, f := range files {
		out := map[string]any{"case": strings.TrimSuffix(filepath.Base(f), ".eml")}
		raw, err := os.ReadFile(f)
		if err != nil {
			out["error"] = err.Error()
		} else if m, err := mail.ReadMessage(bytes.NewReader(raw)); err != nil {
			out["error"] = err.Error()
		} else {
			out["received_count"] = len(m.Header["Received"])
			out["from_in_headers"] = m.Header.Get("From") != ""
			out["field_count"] = len(m.Header)
		}
		b, _ := json.Marshal(out)
		fmt.Println(string(b))
	}
}
