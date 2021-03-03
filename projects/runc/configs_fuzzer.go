package configs

import(
	"fmt"
)


func Fuzz(data []byte) int {
	hookNameList := []string {"prestart",
				  "createRuntime",
				  "createContainer",
				  "startContainer",
				  "poststart"}

	for _, hookName := range hookNameList {
		hooks := Hooks{}
		_ = hooks.UnmarshalJSON([]byte(fmt.Sprintf(`{"%s" :[%s]}`, hookName, data)))
	}
	return 1
}
