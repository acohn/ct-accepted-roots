// Install schema-generate first: go get github.com/a-h/generate/cmd/schema-generate
// Latest schema is at  https://www.gstatic.com/ct/log_list/log_list_schema.json
//go:generate schema-generate -i log_list_schema.json -o schema.go -p schema

package schema
