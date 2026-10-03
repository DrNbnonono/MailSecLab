package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/mail"
	"os"
)

func main() {
	out := map[string]any{"received_count": 0, "from_in_headers": false, "error": ""}
	m, err := mail.ReadMessage(bufio.NewReader(os.Stdin))
	if err != nil {
		out["error"] = err.Error()
	} else {
		out["received_count"] = len(m.Header["Received"])
		out["from_in_headers"] = m.Header.Get("From") != ""
	}
	b, _ := json.Marshal(out)
	fmt.Println(string(b))
}
