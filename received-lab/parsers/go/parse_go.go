package main

// Phase 3C parser: Go net/mail (stdlib). Interprets one .eml and reports the
// structure as *this parser* sees it. net/mail (textproto) stops the header
// section at the first malformed line; the body starts there.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/mail"
	"os"
	"runtime"
	"strings"
)

type result struct {
	Parser           string   `json:"parser"`
	Version          string   `json:"version"`
	ParseError       *string  `json:"parse_error"`
	Defects          []string `json:"defects"`
	HeaderEntries    int      `json:"header_entries"`
	ReceivedCount    int      `json:"received_count"`
	FromPresent      bool     `json:"from_present"`
	SubjectPresent   bool     `json:"subject_present"`
	MessageIDPresent bool     `json:"message_id_present"`
	FromInBody       bool     `json:"from_in_body"`
	SubjectInBody    bool     `json:"subject_in_body"`
}

func main() {
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	o := result{Parser: "go-net-mail", Version: runtime.Version(), Defects: []string{}}

	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		s := err.Error()
		o.ParseError = &s
	}
	if msg != nil {
		total, received := 0, 0
		for k, v := range msg.Header {
			total += len(v)
			if strings.EqualFold(k, "Received") {
				received += len(v)
			}
		}
		o.HeaderEntries = total
		o.ReceivedCount = received
		o.FromPresent = msg.Header.Get("From") != ""
		o.SubjectPresent = msg.Header.Get("Subject") != ""
		o.MessageIDPresent = msg.Header.Get("Message-ID") != ""
		body, _ := io.ReadAll(msg.Body)
		s := string(body)
		o.FromInBody = strings.Contains(s, "From: Alice")
		o.SubjectInBody = strings.Contains(s, "Subject: [")
	}
	b, _ := json.Marshal(o)
	fmt.Println(string(b))
}
