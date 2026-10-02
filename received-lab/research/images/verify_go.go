package main

import (
 "bytes"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "io"
 "os"
 "strings"
 "github.com/emersion/go-msgauth/dkim"
)

func main() {
 raw, err := io.ReadAll(os.Stdin)
 if err != nil { panic(err) }
 digest := sha256.Sum256(raw)
 out := map[string]interface{}{"status":"none", "input_sha256":hex.EncodeToString(digest[:]), "signatures":[]interface{}{}}
 verifications, err := dkim.Verify(bytes.NewReader(raw))
 if err != nil { out["status"]="parse-error"; out["error"]=err.Error() }
 sigs := []map[string]interface{}{}
 for _, v := range verifications {
  state, detail := "pass", ""
  if v.Err != nil {
   detail = v.Err.Error()
   if dkim.IsTempFail(v.Err) { state="temp-error" } else if strings.Contains(detail,"insecure body length") { state="policy-reject" } else if dkim.IsPermFail(v.Err) { state="parse-error" } else { state="fail" }
  }
  sigs=append(sigs,map[string]interface{}{"status":state,"detail":detail,"domain":v.Domain,"h":v.HeaderKeys})
 }
 if len(sigs)>0 { out["status"]=sigs[0]["status"] }
 out["signatures"]=sigs
 encoded, err := json.Marshal(out)
 if err != nil { panic(err) }
 fmt.Println(string(encoded))
}
