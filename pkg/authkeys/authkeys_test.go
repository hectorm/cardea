package authkeys

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hectorm/cardea/pkg/timewindow"
)

func TestAuthkeys(t *testing.T) {
	t.Run("parse_file", func(t *testing.T) {
		aliceKeyAuth := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		bobKeyAuth := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
		carolKeyAuth := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"

		marshalKey := func(s string) string {
			key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(s))
			if err != nil {
				t.Fatalf("failed to parse test key: %v", err)
			}
			return string(key.Marshal())
		}
		aliceKeyMarshal := marshalKey(aliceKeyAuth)
		bobKeyMarshal := marshalKey(bobKeyAuth)
		carolKeyMarshal := marshalKey(carolKeyAuth)

		defaultPermitOpens := []PermitTCP{
			{Host: "localhost", Port: "1-65535"},
			{Host: "127.0.0.1/8", Port: "1-65535"},
			{Host: "::1/128", Port: "1-65535"},
		}

		t.Run("valid", func(t *testing.T) {
			tests := []struct {
				name    string
				content string
				want    map[string][]*AuthorizedKeyOptions
			}{
				{
					name: "macro_key_expansion",
					content: fmt.Sprintf(`
					#define ALICE_KEY %s
					permitconnect="*@macro-key.example.com:22" ALICE_KEY
					`, aliceKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						aliceKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "macro-key.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens}},
					},
				},
				{
					name: "macro_in_permitconnect_value",
					content: fmt.Sprintf(`
					#define PERMITCONNECT_GROUP *@10.0.1.0/24:22,*@macro-value.example.com:22
					permitconnect="PERMITCONNECT_GROUP" %s
					`, bobKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						bobKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "10.0.1.0/24", Port: "22"}, {User: "*", Host: "macro-value.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens}},
					},
				},
				{
					name: "macro_multiline_expansion",
					content: fmt.Sprintf(`
					#define MULTILINE_SERVERS \
					# dev network
					*@10.0.0.0/24:22, \
					# dev server
					*@multiline-macro.example.com:22
					permitconnect="MULTILINE_SERVERS" %s
					`, carolKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						carolKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "10.0.0.0/24", Port: "22"}, {User: "*", Host: "multiline-macro.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens}},
					},
				},
				{
					name: "macro_composed_expansion",
					content: fmt.Sprintf(`
					#define PERMITCONNECT_GROUP *@10.0.1.0/24:22,*@macro-value.example.com:22
					#define MULTILINE_SERVERS \
					*@10.0.0.0/24:22, \
					*@multiline-macro.example.com:22
					#define COMPOSED_SERVERS MULTILINE_SERVERS,PERMITCONNECT_GROUP
					permitconnect="COMPOSED_SERVERS" %s
					`, aliceKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						aliceKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "10.0.0.0/24", Port: "22"}, {User: "*", Host: "multiline-macro.example.com", Port: "22"}, {User: "*", Host: "10.0.1.0/24", Port: "22"}, {User: "*", Host: "macro-value.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens}},
					},
				},
				{
					name: "macro_nested_within_depth",
					content: fmt.Sprintf(`
					#define ALICE_KEY %s
					#define NESTED_L0 NESTED_L1
					#define NESTED_L1 NESTED_L2
					#define NESTED_L2 NESTED_L3
					#define NESTED_L3 NESTED_L4
					#define NESTED_L4 NESTED_L5
					#define NESTED_L5 NESTED_L6
					#define NESTED_L6 NESTED_L7
					#define NESTED_L7 NESTED_L8
					#define NESTED_L8 ALICE_KEY
					permitconnect="*@nested-macro.example.com:22" NESTED_L0
					`, aliceKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						aliceKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "nested-macro.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens}},
					},
				},
				{
					name: "macro_empty_value",
					content: fmt.Sprintf(`
					#define EMPTY_MACRO
					permitconnect="*@empty-macro.example.com:22" EMPTY_MACRO %s
					`, aliceKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						aliceKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "empty-macro.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens}},
					},
				},
				{
					name: "macro_whitespace_padded_value",
					content: fmt.Sprintf(`
					#define PADDED_SERVERS   *@padded-macro.example.com:22
					permitconnect="PADDED_SERVERS" %s
					`, aliceKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						aliceKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "padded-macro.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens}},
					},
				},
				{
					name: "macro_redefinition_last_wins",
					content: fmt.Sprintf(`
					#define REDEFINED_SERVERS *@redef-first.example.com:22
					#define REDEFINED_SERVERS *@redef-last.example.com:22
					permitconnect="REDEFINED_SERVERS" %s
					`, aliceKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						aliceKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "redef-last.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens}},
					},
				},
				{
					name: "macro_redefinition_sequential",
					content: fmt.Sprintf(`
					#define SEQUENTIAL_SERVERS *@seq-first.example.com:22
					permitconnect="SEQUENTIAL_SERVERS" %s
					#define SEQUENTIAL_SERVERS *@seq-second.example.com:22
					permitconnect="SEQUENTIAL_SERVERS" %s
					`, aliceKeyAuth, bobKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						aliceKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "seq-first.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens}},
						bobKeyMarshal:   {{PermitConnects: []PermitConnect{{User: "*", Host: "seq-second.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens}},
					},
				},
				{
					name: "macro_token_boundary",
					content: fmt.Sprintf(`
					#define ALICE_KEY %s
					#define HOST expanded.example.com
					permitconnect="*@HOST:22,*@HOSTNAME:22,*@PREHOST:22" ALICE_KEY
					`, aliceKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						aliceKeyMarshal: {{PermitConnects: []PermitConnect{
							{User: "*", Host: "expanded.example.com", Port: "22"},
							{User: "*", Host: "hostname", Port: "22"},
							{User: "*", Host: "prehost", Port: "22"},
						}, PermitOpens: defaultPermitOpens}},
					},
				},
				{
					name:    "macro_tab_separator",
					content: fmt.Sprintf("#define\tTAB_SERVERS *@tab-define.example.com:22\npermitconnect=\"TAB_SERVERS\" %s\n", aliceKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						aliceKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "tab-define.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens}},
					},
				},
				{
					name: "macro_underscore_prefixed_name",
					content: fmt.Sprintf(`
					#define _UNDERSCORE_SERVERS *@underscore-prefix.example.com:22
					permitconnect="_UNDERSCORE_SERVERS" %s
					`, aliceKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						aliceKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "underscore-prefix.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens}},
					},
				},
				{
					name: "macro_alphanumeric_name",
					content: fmt.Sprintf(`
					#define SERVER_GROUP_123 *@alphanumeric-name.example.com:22
					permitconnect="SERVER_GROUP_123" %s
					`, aliceKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						aliceKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "alphanumeric-name.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens}},
					},
				},
				{
					name:    "macro_at_eof_without_newline",
					content: fmt.Sprintf("#define EOF_SERVERS *@eof-no-newline.example.com:22\npermitconnect=\"EOF_SERVERS\" %s", aliceKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						aliceKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "eof-no-newline.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens}},
					},
				},
				{
					name: "macro_adjacent_hash",
					content: fmt.Sprintf(`
					#define HASH_ADJACENT_HOST hash-adjacent.example.com
					permitconnect="*@HASH_ADJACENT_HOST:22,*@other#host.example.com:22" %s
					`, aliceKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						aliceKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "hash-adjacent.example.com", Port: "22"}, {User: "*", Host: "other#host.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens}},
					},
				},
				{
					name: "macro_option_template",
					content: fmt.Sprintf(`
					#define SFTP_OPTIONS command="internal-sftp",no-pty
					permitconnect="*@opts-template.example.com:22",SFTP_OPTIONS %s
					`, aliceKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						aliceKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "opts-template.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens, Command: "internal-sftp", NoPty: true}},
					},
				},
				{
					name: "macro_parameterized_hostname",
					content: fmt.Sprintf(`
					#define APP_ENV prod
					#define APP_REGION us
					#define APP_HOST app.APP_ENV.APP_REGION.example.com
					permitconnect="*@APP_HOST:22" %s
					`, bobKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						bobKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "app.prod.us.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens}},
					},
				},
				{
					name: "macro_hierarchical_groups",
					content: fmt.Sprintf(`
					#define TIER_ONE_SERVERS *@hierarchy-1.example.com:22
					#define TIER_TWO_SERVERS TIER_ONE_SERVERS,*@hierarchy-2.example.com:22
					permitconnect="TIER_TWO_SERVERS" %s
					`, carolKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						carolKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "hierarchy-1.example.com", Port: "22"}, {User: "*", Host: "hierarchy-2.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens}},
					},
				},
				{
					name: "macro_full_line_template",
					content: fmt.Sprintf(`
					#define LINE_TEMPLATE permitconnect="*@line-template.example.com:22"
					LINE_TEMPLATE %s
					`, aliceKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						aliceKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "line-template.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens}},
					},
				},
				{
					name: "macro_option_composition",
					content: fmt.Sprintf(`
					#define NO_PTY_OPTION no-pty
					#define NO_PORT_FORWARDING_OPTION no-port-forwarding
					#define COMPOSED_OPTIONS NO_PTY_OPTION,NO_PORT_FORWARDING_OPTION
					permitconnect="*@opts-composed.example.com:22",COMPOSED_OPTIONS %s
					`, bobKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						bobKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "opts-composed.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens, NoPortForwarding: true, NoPty: true}},
					},
				},
				{
					name: "macro_port_abstraction",
					content: fmt.Sprintf(`
					#define ABSTRACT_PORT 22
					#define ABSTRACT_HOST port-abstract.example.com
					permitconnect="*@ABSTRACT_HOST:ABSTRACT_PORT" %s
					`, carolKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						carolKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "port-abstract.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens}},
					},
				},
				{
					name: "macro_user_pattern",
					content: fmt.Sprintf(`
					#define ADMIN_USER admin
					permitconnect="ADMIN_USER@user-pattern.example.com:22" %s
					`, aliceKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						aliceKeyMarshal: {{PermitConnects: []PermitConnect{{User: "admin", Host: "user-pattern.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens}},
					},
				},
				{
					name: "macro_in_multiple_option_values",
					content: fmt.Sprintf(`
					#define MULTI_OPTION_HOST multi-option.example.com
					permitconnect="*@MULTI_OPTION_HOST:22",permitopen="MULTI_OPTION_HOST:80" %s
					`, bobKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						bobKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "multi-option.example.com", Port: "22"}}, PermitOpens: []PermitTCP{{Host: "multi-option.example.com", Port: "80"}}}},
					},
				},
				{
					name: "macro_braced",
					content: fmt.Sprintf(`
					#define {{BRACED_NAME}} expanded.example.com
					permitconnect="*@{{BRACED_NAME}}:22" %s BRACED_NAME
					`, aliceKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						aliceKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "expanded.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens, Comment: "BRACED_NAME"}},
					},
				},
				{
					name: "macro_bare_at_braced_reference",
					content: fmt.Sprintf(`
					#define BARE_NAME expanded
					permitconnect="*@{{BARE_NAME}}.example.com:22" %s {{BARE_NAME}}suffix
					`, aliceKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						aliceKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "expanded.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens, Comment: "expandedsuffix"}},
					},
				},
				{
					name: "macro_braced_unclosed_stays_literal",
					content: fmt.Sprintf(`
					#define {{NAME}} should-not-expand
					permitconnect="*@{{NAME}.example.com:22" %s
					`, aliceKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						aliceKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "{{name}.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens}},
					},
				},
				{
					name: "macro_containing_pipe",
					content: fmt.Sprintf(`
					#define PIPE_TEAM %s | PIPE_DEFERRED
					#define PIPE_DEFERRED %s
					permitconnect="*@macro-pipe.example.com:22" PIPE_TEAM
					`, aliceKeyAuth, bobKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						aliceKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "macro-pipe.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens}},
						bobKeyMarshal:   {{PermitConnects: []PermitConnect{{User: "*", Host: "macro-pipe.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens}},
					},
				},
				{
					name: "macro_nested_team_composition",
					content: fmt.Sprintf(`
					#define NESTED_SUBTEAM_A %s
					#define NESTED_SUBTEAM_B %s | %s
					#define NESTED_TEAM NESTED_SUBTEAM_A | NESTED_SUBTEAM_B
					permitconnect="*@nested-team.example.com:22" NESTED_TEAM
					`, aliceKeyAuth, bobKeyAuth, carolKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						aliceKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "nested-team.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens}},
						bobKeyMarshal:   {{PermitConnects: []PermitConnect{{User: "*", Host: "nested-team.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens}},
						carolKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "nested-team.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens}},
					},
				},
				{
					name: "macro_escaped_comment",
					content: fmt.Sprintf(`
					#define {{BRACED_NAME}} expanded.example.com
					permitconnect="*@comment-escape.example.com:22" %s \{{BRACED_NAME}}
					`, aliceKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						aliceKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "comment-escape.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens, Comment: "{{BRACED_NAME}}"}},
					},
				},
				{
					name: "macro_escaped_command",
					content: fmt.Sprintf(`
					#define {{BRACED_NAME}} expanded.example.com
					permitconnect="*@command-escape.example.com:22",command="\{{BRACED_NAME}}" %s
					`, aliceKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						aliceKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "command-escape.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens, Command: "{{BRACED_NAME}}"}},
					},
				},
				{
					name: "macro_escaped_invalid_stays_literal",
					content: fmt.Sprintf(`
					#define {{BRACED_NAME}} expanded.example.com
					permitconnect="*@invalid-escape.example.com:22" %s \{{123}}
					`, aliceKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						aliceKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "invalid-escape.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens, Comment: "\\{{123}}"}},
					},
				},
				{
					name: "macro_escaped_unterminated_stays_literal",
					content: fmt.Sprintf(`
					permitconnect="*@unterminated-escape.example.com:22" %s \{{NOPE
					`, aliceKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						aliceKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "unterminated-escape.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens, Comment: "\\{{NOPE"}},
					},
				},
				{
					name: "pipe_consecutive_continuations",
					content: fmt.Sprintf(`
					permitconnect="*@pipe-continuation.example.com:22" %s \
					\
					\
					| %s
					`, aliceKeyAuth, carolKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						aliceKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "pipe-continuation.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens}},
						carolKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "pipe-continuation.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens}},
					},
				},
				{
					name:    "pipe_empty_segments",
					content: fmt.Sprintf(`|permitconnect="*@empty-pipes.example.com:22" %s||%s|||%s|`, aliceKeyAuth, bobKeyAuth, carolKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						aliceKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "empty-pipes.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens}},
						bobKeyMarshal:   {{PermitConnects: []PermitConnect{{User: "*", Host: "empty-pipes.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens}},
						carolKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "empty-pipes.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens}},
					},
				},
				{
					name:    "pipe_key_comments",
					content: fmt.Sprintf(`permitconnect="*@pipe-comments.example.com:22" %s alice | %s bob`, aliceKeyAuth, bobKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						aliceKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "pipe-comments.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens, Comment: "alice"}},
						bobKeyMarshal:   {{PermitConnects: []PermitConnect{{User: "*", Host: "pipe-comments.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens, Comment: "bob"}},
					},
				},
				{
					name: "inline_comment_on_define_key",
					content: fmt.Sprintf(`
					#define INLINE_KEY %s # This is an inline comment
					permitconnect="*@inline-define-key.example.com:22" INLINE_KEY
					`, aliceKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						aliceKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "inline-define-key.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens}},
					},
				},
				{
					name: "inline_comment_on_define_team",
					content: fmt.Sprintf(`
					#define INLINE_TEAM %s | %s # Team with inline comment
					permitconnect="*@inline-define-team.example.com:22" INLINE_TEAM
					`, aliceKeyAuth, bobKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						aliceKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "inline-define-team.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens}},
						bobKeyMarshal:   {{PermitConnects: []PermitConnect{{User: "*", Host: "inline-define-team.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens}},
					},
				},
				{
					name: "inline_comment_at_end_of_multiline_define",
					content: fmt.Sprintf(`
					#define INLINE_MULTILINE_SERVERS \
					*@inline-multiline-1.example.com:22, \
					*@inline-multiline-2.example.com:22 # Inline comment at end of multi-line
					permitconnect="INLINE_MULTILINE_SERVERS" %s
					`, aliceKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						aliceKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "inline-multiline-1.example.com", Port: "22"}, {User: "*", Host: "inline-multiline-2.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens}},
					},
				},
				{
					name:    "inline_comment_on_rule",
					content: fmt.Sprintf(`permitconnect="*@inline-rule.example.com:22" %s # Rule with inline comment`, aliceKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						aliceKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "inline-rule.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens}},
					},
				},
				{
					name:    "inline_comment_on_rule_pipe",
					content: fmt.Sprintf(`permitconnect="*@inline-rule-pipe.example.com:22" %s | %s # Rule with pipe and inline comment`, aliceKeyAuth, bobKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						aliceKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "inline-rule-pipe.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens}},
						bobKeyMarshal:   {{PermitConnects: []PermitConnect{{User: "*", Host: "inline-rule-pipe.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens}},
					},
				},
				{
					name:    "hash_in_quoted_value",
					content: fmt.Sprintf(`permitconnect="#user@hash#host.example.com:22",command="echo # not a comment" %s # a comment`, aliceKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						aliceKeyMarshal: {{PermitConnects: []PermitConnect{{User: "#user", Host: "hash#host.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens, Command: "echo # not a comment"}},
					},
				},
				{
					name:    "crlf_comment",
					content: fmt.Sprintf("# comment\r\npermitconnect=\"*@crlf-comment.example.com:22\" %s\n", aliceKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						aliceKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "crlf-comment.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens}},
					},
				},
				{
					name: "line_continuation_lf",
					content: fmt.Sprintf(`
					permitconnect="*@line-cont-lf.example.com:22",permitopen="*:80,*:443" \
					# comment
					%s
					`, bobKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						bobKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "line-cont-lf.example.com", Port: "22"}}, PermitOpens: []PermitTCP{{Host: "*", Port: "80"}, {Host: "*", Port: "443"}}}},
					},
				},
				{
					name:    "line_continuation_crlf",
					content: fmt.Sprintf("permitconnect=\"*@line-cont-crlf.example.com:22\",permitopen=\"*:80,*:443\" \\\r\n%s\n", carolKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						carolKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "line-cont-crlf.example.com", Port: "22"}}, PermitOpens: []PermitTCP{{Host: "*", Port: "80"}, {Host: "*", Port: "443"}}}},
					},
				},
				{
					name:    "pipe_in_quoted_command",
					content: fmt.Sprintf(`permitconnect="*@pipe-in-command.example.com:22",command="echo hello | grep h" %s`, bobKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						bobKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "pipe-in-command.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens, Command: "echo hello | grep h"}},
					},
				},
				{
					name:    "escaped_quotes_in_command",
					content: fmt.Sprintf(`permitconnect="*@escaped-quotes.example.com:22",command="echo \"hello\"" %s`, aliceKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						aliceKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "escaped-quotes.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens, Command: `echo "hello"`}},
					},
				},
				{
					name:    "escaped_backslash_in_command",
					content: fmt.Sprintf(`permitconnect="*@escaped-backslash.example.com:22",command="echo C:\\path\\file" %s`, aliceKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						aliceKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "escaped-backslash.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens, Command: `echo C:\\path\\file`}},
					},
				},
				{
					name:    "key_comment",
					content: fmt.Sprintf(`permitconnect="*@comment.example.com:22" %s alice@laptop`, aliceKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						aliceKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "comment.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens, Comment: "alice@laptop"}},
					},
				},
				{
					name: "unclosed_quote_line_isolation",
					content: fmt.Sprintf(`
					permitconnect="*@unclosed-quote.example.com:22" %s unclosed="value
					permitconnect="*@after-unclosed.example.com:22" %s
					`, bobKeyAuth, aliceKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						aliceKeyMarshal: {{PermitConnects: []PermitConnect{{User: "*", Host: "after-unclosed.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens}},
					},
				},
				{
					name: "multiple_declarations_same_option",
					content: fmt.Sprintf(`
					permitconnect="*@multi-decl-1.example.com:22",permitconnect="*@multi-decl-2.example.com:22",\
					permitopen="*:80",permitopen="*:443",\
					permitlisten="localhost:8080",permitlisten="localhost:9090",\
					permitsocketopen="/tmp/first.sock",permitsocketopen="/tmp/last.sock",\
					permitsocketlisten="/tmp/first.sock",permitsocketlisten="/tmp/last.sock",\
					environment="FOO=bar",environment="BAZ=quux",\
					from="10.0.0.0/8",from="172.16.0.0/12",\
					start-time="20060101Z",start-time="20060102Z",\
					expiry-time="20060101Z",expiry-time="20060102Z",\
					time-window="dow:mon-thu hour:8-17 tz:Europe/Madrid",time-window="dow:fri hour:8-14 tz:Europe/Madrid",\
					command="first",command="last",\
					no-port-forwarding,port-forwarding,\
					no-socket-forwarding,socket-forwarding,\
					no-pty,pty,\
					no-recording,recording \
					%s
					`, aliceKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						aliceKeyMarshal: {{
							PermitConnects:      []PermitConnect{{User: "*", Host: "multi-decl-1.example.com", Port: "22"}, {User: "*", Host: "multi-decl-2.example.com", Port: "22"}},
							PermitOpens:         []PermitTCP{{Host: "*", Port: "80"}, {Host: "*", Port: "443"}},
							PermitListens:       []PermitTCP{{Host: "localhost", Port: "8080"}, {Host: "localhost", Port: "9090"}},
							PermitSocketOpens:   []PermitSocket{{Path: "/tmp/first.sock"}, {Path: "/tmp/last.sock"}},
							PermitSocketListens: []PermitSocket{{Path: "/tmp/first.sock"}, {Path: "/tmp/last.sock"}},
							Environments:        []Environment{{Name: "FOO", Value: "bar"}, {Name: "BAZ", Value: "quux"}},
							Froms:               []string{"10.0.0.0/8", "172.16.0.0/12"},
							StartTime:           func() *time.Time { t := time.Date(2006, 1, 2, 0, 0, 0, 0, time.UTC); return &t }(),
							ExpiryTime:          func() *time.Time { t := time.Date(2006, 1, 1, 0, 0, 0, 0, time.UTC); return &t }(),
							TimeWindow: func() *timewindow.TimeWindow {
								tw, _ := timewindow.Parse("dow:mon-thu hour:8-17 tz:Europe/Madrid,dow:fri hour:8-14 tz:Europe/Madrid")
								return tw
							}(),
							Command: "last",
						}},
					},
				},
				{
					name: "multiple_entries_same_key",
					content: fmt.Sprintf(`
					permitconnect="*@multi-entry-1.example.com:22" %s
					permitconnect="*@multi-entry-2.example.com:22" %s
					`, aliceKeyAuth, aliceKeyAuth),
					want: map[string][]*AuthorizedKeyOptions{
						aliceKeyMarshal: {
							{PermitConnects: []PermitConnect{{User: "*", Host: "multi-entry-1.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens},
							{PermitConnects: []PermitConnect{{User: "*", Host: "multi-entry-2.example.com", Port: "22"}}, PermitOpens: defaultPermitOpens},
						},
					},
				},
			}

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					got, _, err := ParseFile([]byte(tt.content))
					if err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
					if len(got) != len(tt.want) {
						t.Errorf("expected %d keys in authorized_keys db, got %d", len(tt.want), len(got))
						return
					}
					for key, optsList := range got {
						expectedOptsList, ok := tt.want[key]
						if !ok {
							t.Error("expected key to be in authorized_keys db, but it was not found")
							return
						}
						if len(optsList) != len(expectedOptsList) {
							t.Errorf("expected %d options for key, got %d", len(expectedOptsList), len(optsList))
							return
						}
						for i, opts := range optsList {
							expectedOpts := expectedOptsList[i]
							if len(opts.PermitConnects) != len(expectedOpts.PermitConnects) {
								t.Errorf("expected %d permitconnects for key, got %d", len(expectedOpts.PermitConnects), len(opts.PermitConnects))
								return
							}
							for j, pc := range opts.PermitConnects {
								expectedPC := expectedOpts.PermitConnects[j]
								if pc.User != expectedPC.User || pc.Host != expectedPC.Host || pc.Port != expectedPC.Port {
									t.Errorf("expected permitconnect %v for key, got %v", expectedPC, pc)
									return
								}
							}
							if len(opts.PermitOpens) != len(expectedOpts.PermitOpens) {
								t.Errorf("expected %d permitopens for key, got %d", len(expectedOpts.PermitOpens), len(opts.PermitOpens))
								return
							}
							for j, po := range opts.PermitOpens {
								expectedPO := expectedOpts.PermitOpens[j]
								if po.Host != expectedPO.Host || po.Port != expectedPO.Port {
									t.Errorf("expected permitopen %v for key, got %v", expectedPO, po)
									return
								}
							}
							if len(opts.PermitListens) != len(expectedOpts.PermitListens) {
								t.Errorf("expected %d permitlistens for key, got %d", len(expectedOpts.PermitListens), len(opts.PermitListens))
								return
							}
							for j, pl := range opts.PermitListens {
								expectedPL := expectedOpts.PermitListens[j]
								if pl.Host != expectedPL.Host || pl.Port != expectedPL.Port {
									t.Errorf("expected permitlisten %v for key, got %v", expectedPL, pl)
									return
								}
							}
							if len(opts.PermitSocketOpens) != len(expectedOpts.PermitSocketOpens) {
								t.Errorf("expected %d permitsocketopens for key, got %d", len(expectedOpts.PermitSocketOpens), len(opts.PermitSocketOpens))
								return
							}
							for j, pso := range opts.PermitSocketOpens {
								expectedPSO := expectedOpts.PermitSocketOpens[j]
								if pso.Path != expectedPSO.Path {
									t.Errorf("expected permitsocketopen %v for key, got %v", expectedPSO, pso)
									return
								}
							}
							if len(opts.PermitSocketListens) != len(expectedOpts.PermitSocketListens) {
								t.Errorf("expected %d permitsocketlistens for key, got %d", len(expectedOpts.PermitSocketListens), len(opts.PermitSocketListens))
								return
							}
							for j, psl := range opts.PermitSocketListens {
								expectedPSL := expectedOpts.PermitSocketListens[j]
								if psl.Path != expectedPSL.Path {
									t.Errorf("expected permitsocketlisten %v for key, got %v", expectedPSL, psl)
									return
								}
							}
							if len(opts.Environments) != len(expectedOpts.Environments) {
								t.Errorf("expected %d environments for key, got %d", len(expectedOpts.Environments), len(opts.Environments))
								return
							}
							for j, env := range opts.Environments {
								if env != expectedOpts.Environments[j] {
									t.Errorf("expected environment %+v for key, got %+v", expectedOpts.Environments[j], env)
									return
								}
							}
							if len(opts.Froms) != len(expectedOpts.Froms) {
								t.Errorf("expected %d froms for key, got %d", len(expectedOpts.Froms), len(opts.Froms))
								return
							}
							for j, from := range opts.Froms {
								if from != expectedOpts.Froms[j] {
									t.Errorf("expected from %q for key, got %q", expectedOpts.Froms[j], from)
									return
								}
							}
							if (opts.StartTime == nil) != (expectedOpts.StartTime == nil) {
								t.Errorf("expected start-time %v for key, got %v", expectedOpts.StartTime, opts.StartTime)
								return
							}
							if opts.StartTime != nil && !opts.StartTime.Equal(*expectedOpts.StartTime) {
								t.Errorf("expected start-time %v for key, got %v", *expectedOpts.StartTime, *opts.StartTime)
								return
							}
							if (opts.ExpiryTime == nil) != (expectedOpts.ExpiryTime == nil) {
								t.Errorf("expected expiry-time %v for key, got %v", expectedOpts.ExpiryTime, opts.ExpiryTime)
								return
							}
							if opts.ExpiryTime != nil && !opts.ExpiryTime.Equal(*expectedOpts.ExpiryTime) {
								t.Errorf("expected expiry-time %v for key, got %v", *expectedOpts.ExpiryTime, *opts.ExpiryTime)
								return
							}
							if (opts.TimeWindow == nil) != (expectedOpts.TimeWindow == nil) {
								t.Errorf("expected time-window %v for key, got %v", expectedOpts.TimeWindow, opts.TimeWindow)
								return
							}
							if opts.TimeWindow != nil && opts.TimeWindow.String() != expectedOpts.TimeWindow.String() {
								t.Errorf("expected time-window %s for key, got %s", expectedOpts.TimeWindow, opts.TimeWindow)
								return
							}
							if opts.Command != expectedOpts.Command {
								t.Errorf("expected command %q for key, got %q", expectedOpts.Command, opts.Command)
								return
							}
							if opts.NoPortForwarding != expectedOpts.NoPortForwarding {
								t.Errorf("expected no-port-forwarding %t for key, got %t", expectedOpts.NoPortForwarding, opts.NoPortForwarding)
								return
							}
							if opts.NoSocketForwarding != expectedOpts.NoSocketForwarding {
								t.Errorf("expected no-socket-forwarding %t for key, got %t", expectedOpts.NoSocketForwarding, opts.NoSocketForwarding)
								return
							}
							if opts.NoPty != expectedOpts.NoPty {
								t.Errorf("expected no-pty %t for key, got %t", expectedOpts.NoPty, opts.NoPty)
								return
							}
							if opts.NoRecording != expectedOpts.NoRecording {
								t.Errorf("expected no-recording %t for key, got %t", expectedOpts.NoRecording, opts.NoRecording)
								return
							}
							if opts.Comment != expectedOpts.Comment {
								t.Errorf("expected comment %q for key, got %q", expectedOpts.Comment, opts.Comment)
								return
							}
						}
					}
				})
			}
		})

		t.Run("ignored", func(t *testing.T) {
			tests := []struct {
				name    string
				content string
			}{
				{name: "empty_file", content: ``},
				{name: "whitespace_only", content: `   `},
				{name: "tabs_and_newlines", content: "\t\n\t\n"},
				{name: "comment_only", content: "# comment only\n# another comment"},
				{name: "pipe_only", content: "|"},
				{name: "pipe_whitespace_segments", content: `   |   |   `},
			}

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					db, warnings, err := ParseFile([]byte(tt.content))
					if err != nil {
						t.Fatalf("ParseFile returned error: %v", err)
					}
					if len(warnings) != 0 {
						t.Errorf("expected no warnings, got %d", len(warnings))
					}
					if len(db) != 0 {
						t.Errorf("expected empty db, got %d keys", len(db))
					}
				})
			}
		})

		t.Run("invalid", func(t *testing.T) {
			tests := []struct {
				name    string
				content string
			}{
				{name: "invalid_ssh_key", content: `permitconnect="*@example.com:22" invalid`},
				// Key without options
				{name: "key_without_options", content: aliceKeyAuth},
				// Options without permitconnect
				{name: "options_without_permitconnect", content: fmt.Sprintf(`command="nologin" %s`, aliceKeyAuth)},
				// Invalid permitconnect
				{name: "permitconnect_empty", content: fmt.Sprintf(`permitconnect="" %s`, aliceKeyAuth)},
				{name: "permitconnect_invalid_format", content: fmt.Sprintf(`permitconnect="invalid" %s`, aliceKeyAuth)},
				{name: "permitconnect_missing_user_at", content: fmt.Sprintf(`permitconnect="@host:22" %s`, aliceKeyAuth)},
				{name: "permitconnect_missing_host_at", content: fmt.Sprintf(`permitconnect="user@:22" %s`, aliceKeyAuth)},
				{name: "permitconnect_missing_port_at", content: fmt.Sprintf(`permitconnect="user@host:" %s`, aliceKeyAuth)},
				{name: "permitconnect_missing_user_plus", content: fmt.Sprintf(`permitconnect="+host+22" %s`, aliceKeyAuth)},
				{name: "permitconnect_missing_host_plus", content: fmt.Sprintf(`permitconnect="user++22" %s`, aliceKeyAuth)},
				{name: "permitconnect_missing_port_plus", content: fmt.Sprintf(`permitconnect="user+host+" %s`, aliceKeyAuth)},
				{name: "permitconnect_empty_user_and_host_at", content: fmt.Sprintf(`permitconnect="@:22" %s`, aliceKeyAuth)},
				{name: "permitconnect_empty_user_and_host_plus", content: fmt.Sprintf(`permitconnect="++22" %s`, aliceKeyAuth)},
				{name: "permitconnect_exceeding_length_at", content: fmt.Sprintf(`permitconnect="*@%s:22" %s`, strings.Repeat("a", 1100), aliceKeyAuth)},
				{name: "permitconnect_exceeding_length_plus", content: fmt.Sprintf(`permitconnect="*+%s+22" %s`, strings.Repeat("a", 1100), aliceKeyAuth)},
				// Invalid permitopen
				{name: "permitopen_empty", content: fmt.Sprintf(`permitconnect="*@example.com:22",permitopen="" %s`, aliceKeyAuth)},
				{name: "permitopen_invalid_format", content: fmt.Sprintf(`permitconnect="*@example.com:22",permitopen="invalid" %s`, aliceKeyAuth)},
				{name: "permitopen_missing_host", content: fmt.Sprintf(`permitconnect="*@example.com:22",permitopen=":22" %s`, aliceKeyAuth)},
				{name: "permitopen_missing_port", content: fmt.Sprintf(`permitconnect="*@example.com:22",permitopen="host:" %s`, aliceKeyAuth)},
				{name: "permitopen_exceeding_length", content: fmt.Sprintf(`permitconnect="*@example.com:22",permitopen="%s:22" %s`, strings.Repeat("a", 550), aliceKeyAuth)},
				// Invalid permitlisten
				{name: "permitlisten_empty", content: fmt.Sprintf(`permitconnect="*@example.com:22",permitlisten="" %s`, aliceKeyAuth)},
				{name: "permitlisten_invalid_format", content: fmt.Sprintf(`permitconnect="*@example.com:22",permitlisten="invalid" %s`, aliceKeyAuth)},
				{name: "permitlisten_missing_host", content: fmt.Sprintf(`permitconnect="*@example.com:22",permitlisten=":22" %s`, aliceKeyAuth)},
				{name: "permitlisten_missing_port", content: fmt.Sprintf(`permitconnect="*@example.com:22",permitlisten="host:" %s`, aliceKeyAuth)},
				{name: "permitlisten_exceeding_length", content: fmt.Sprintf(`permitconnect="*@example.com:22",permitlisten="%s:22" %s`, strings.Repeat("a", 550), aliceKeyAuth)},
				// Invalid permitsocketopen
				{name: "permitsocketopen_empty", content: fmt.Sprintf(`permitconnect="*@example.com:22",permitsocketopen="" %s`, aliceKeyAuth)},
				{name: "permitsocketopen_exceeding_length", content: fmt.Sprintf(`permitconnect="*@example.com:22",permitsocketopen="/%s" %s`, strings.Repeat("a", 550), aliceKeyAuth)},
				// Invalid permitsocketlisten
				{name: "permitsocketlisten_empty", content: fmt.Sprintf(`permitconnect="*@example.com:22",permitsocketlisten="" %s`, aliceKeyAuth)},
				{name: "permitsocketlisten_exceeding_length", content: fmt.Sprintf(`permitconnect="*@example.com:22",permitsocketlisten="/%s" %s`, strings.Repeat("a", 550), aliceKeyAuth)},
				// Invalid environment
				{name: "environment_empty", content: fmt.Sprintf(`permitconnect="*@example.com:22",environment="" %s`, aliceKeyAuth)},
				{name: "environment_missing_equals", content: fmt.Sprintf(`permitconnect="*@example.com:22",environment="NOEQUALS" %s`, aliceKeyAuth)},
				{name: "environment_empty_name", content: fmt.Sprintf(`permitconnect="*@example.com:22",environment="=value" %s`, aliceKeyAuth)},
				{name: "environment_invalid_name_hyphen", content: fmt.Sprintf(`permitconnect="*@example.com:22",environment="BAD-NAME=value" %s`, aliceKeyAuth)},
				{name: "environment_invalid_name_dot", content: fmt.Sprintf(`permitconnect="*@example.com:22",environment="BAD.NAME=value" %s`, aliceKeyAuth)},
				{name: "environment_empty_accept_pattern", content: fmt.Sprintf(`permitconnect="*@example.com:22",environment="+" %s`, aliceKeyAuth)},
				{name: "environment_empty_deny_pattern", content: fmt.Sprintf(`permitconnect="*@example.com:22",environment="-" %s`, aliceKeyAuth)},
				{name: "environment_invalid_accept_glob", content: fmt.Sprintf(`permitconnect="*@example.com:22",environment="+VAR[" %s`, aliceKeyAuth)},
				{name: "environment_invalid_deny_glob", content: fmt.Sprintf(`permitconnect="*@example.com:22",environment="-VAR[" %s`, aliceKeyAuth)},
				// Invalid from
				{name: "from_empty", content: fmt.Sprintf(`permitconnect="*@example.com:22",from="" %s`, aliceKeyAuth)},
				// Invalid start-time
				{name: "start_time_empty", content: fmt.Sprintf(`permitconnect="*@example.com:22",start-time="" %s`, aliceKeyAuth)},
				{name: "start_time_invalid_length", content: fmt.Sprintf(`permitconnect="*@example.com:22",start-time="2020Z" %s`, aliceKeyAuth)},
				{name: "start_time_invalid_month", content: fmt.Sprintf(`permitconnect="*@example.com:22",start-time="20201301Z" %s`, aliceKeyAuth)},
				{name: "start_time_invalid_day", content: fmt.Sprintf(`permitconnect="*@example.com:22",start-time="20200132Z" %s`, aliceKeyAuth)},
				{name: "start_time_nonexistent_date", content: fmt.Sprintf(`permitconnect="*@example.com:22",start-time="20200230Z" %s`, aliceKeyAuth)},
				{name: "start_time_invalid_hour", content: fmt.Sprintf(`permitconnect="*@example.com:22",start-time="202001012500Z" %s`, aliceKeyAuth)},
				{name: "start_time_invalid_minute", content: fmt.Sprintf(`permitconnect="*@example.com:22",start-time="202001010060Z" %s`, aliceKeyAuth)},
				{name: "start_time_invalid_second", content: fmt.Sprintf(`permitconnect="*@example.com:22",start-time="20200101000060Z" %s`, aliceKeyAuth)},
				{name: "start_time_non_numeric_ymd", content: fmt.Sprintf(`permitconnect="*@example.com:22",start-time="ABCD0101Z" %s`, aliceKeyAuth)},
				{name: "start_time_non_numeric_ymdhm", content: fmt.Sprintf(`permitconnect="*@example.com:22",start-time="ABCD01010000Z" %s`, aliceKeyAuth)},
				{name: "start_time_non_numeric_ymdhms", content: fmt.Sprintf(`permitconnect="*@example.com:22",start-time="ABCD0101000000Z" %s`, aliceKeyAuth)},
				// Invalid expiry-time
				{name: "expiry_time_empty", content: fmt.Sprintf(`permitconnect="*@example.com:22",expiry-time="" %s`, aliceKeyAuth)},
				{name: "expiry_time_invalid_length", content: fmt.Sprintf(`permitconnect="*@example.com:22",expiry-time="2099Z" %s`, aliceKeyAuth)},
				{name: "expiry_time_invalid_month", content: fmt.Sprintf(`permitconnect="*@example.com:22",expiry-time="20991301Z" %s`, aliceKeyAuth)},
				{name: "expiry_time_invalid_day", content: fmt.Sprintf(`permitconnect="*@example.com:22",expiry-time="20990132Z" %s`, aliceKeyAuth)},
				{name: "expiry_time_nonexistent_date", content: fmt.Sprintf(`permitconnect="*@example.com:22",expiry-time="20990230Z" %s`, aliceKeyAuth)},
				{name: "expiry_time_invalid_hour", content: fmt.Sprintf(`permitconnect="*@example.com:22",expiry-time="209901012500Z" %s`, aliceKeyAuth)},
				{name: "expiry_time_invalid_minute", content: fmt.Sprintf(`permitconnect="*@example.com:22",expiry-time="209901010060Z" %s`, aliceKeyAuth)},
				{name: "expiry_time_invalid_second", content: fmt.Sprintf(`permitconnect="*@example.com:22",expiry-time="20990101000060Z" %s`, aliceKeyAuth)},
				{name: "expiry_time_non_numeric_ymd", content: fmt.Sprintf(`permitconnect="*@example.com:22",expiry-time="ABCD0101Z" %s`, aliceKeyAuth)},
				{name: "expiry_time_non_numeric_ymdhm", content: fmt.Sprintf(`permitconnect="*@example.com:22",expiry-time="ABCD01010000Z" %s`, aliceKeyAuth)},
				{name: "expiry_time_non_numeric_ymdhms", content: fmt.Sprintf(`permitconnect="*@example.com:22",expiry-time="ABCD0101000000Z" %s`, aliceKeyAuth)},
				// Invalid time-window
				{name: "time_window_empty", content: fmt.Sprintf(`permitconnect="*@example.com:22",time-window="" %s`, aliceKeyAuth)},
				{name: "time_window_whitespace_only", content: fmt.Sprintf(`permitconnect="*@example.com:22",time-window="   " %s`, aliceKeyAuth)},
				{name: "time_window_unknown_constraint", content: fmt.Sprintf(`permitconnect="*@example.com:22",time-window="foo:bar" %s`, aliceKeyAuth)},
				{name: "time_window_missing_value", content: fmt.Sprintf(`permitconnect="*@example.com:22",time-window="hour:" %s`, aliceKeyAuth)},
				{name: "time_window_missing_colon", content: fmt.Sprintf(`permitconnect="*@example.com:22",time-window="dow" %s`, aliceKeyAuth)},
				{name: "time_window_hour_out_of_range", content: fmt.Sprintf(`permitconnect="*@example.com:22",time-window="hour:25" %s`, aliceKeyAuth)},
				{name: "time_window_dow_out_of_range", content: fmt.Sprintf(`permitconnect="*@example.com:22",time-window="dow:7" %s`, aliceKeyAuth)},
				{name: "time_window_month_out_of_range", content: fmt.Sprintf(`permitconnect="*@example.com:22",time-window="month:0" %s`, aliceKeyAuth)},
				{name: "time_window_dow_wrap_around", content: fmt.Sprintf(`permitconnect="*@example.com:22",time-window="dow:fri-mon" %s`, aliceKeyAuth)},
				{name: "time_window_hour_wrap_around", content: fmt.Sprintf(`permitconnect="*@example.com:22",time-window="hour:22-6" %s`, aliceKeyAuth)},
				{name: "time_window_invalid_timezone", content: fmt.Sprintf(`permitconnect="*@example.com:22",time-window="tz:Invalid/Zone" %s`, aliceKeyAuth)},
				{name: "time_window_duplicate_constraint", content: fmt.Sprintf(`permitconnect="*@example.com:22",time-window="hour:9 hour:10" %s`, aliceKeyAuth)},
				{name: "time_window_leading_comma", content: fmt.Sprintf(`permitconnect="*@example.com:22",time-window=",dow:mon" %s`, aliceKeyAuth)},
				{name: "time_window_trailing_comma", content: fmt.Sprintf(`permitconnect="*@example.com:22",time-window="dow:mon," %s`, aliceKeyAuth)},
				{name: "time_window_double_comma", content: fmt.Sprintf(`permitconnect="*@example.com:22",time-window="dow:mon,,dow:tue" %s`, aliceKeyAuth)},
				{name: "time_window_negative_number", content: fmt.Sprintf(`permitconnect="*@example.com:22",time-window="hour:-1" %s`, aliceKeyAuth)},
				{name: "time_window_non_integer", content: fmt.Sprintf(`permitconnect="*@example.com:22",time-window="hour:9.5" %s`, aliceKeyAuth)},
				{name: "time_window_overflow", content: fmt.Sprintf(`permitconnect="*@example.com:22",time-window="hour:999999999999" %s`, aliceKeyAuth)},
				{name: "time_window_empty_range_component", content: fmt.Sprintf(`permitconnect="*@example.com:22",time-window="hour:1//5" %s`, aliceKeyAuth)},
				// Quote/line continuation edge cases
				{name: "unterminated_quoted_string", content: fmt.Sprintf(`permitconnect="*@example.com:22 %s`, aliceKeyAuth)},
				{name: "crlf_inside_quoted_string", content: fmt.Sprintf("permitconnect=\"*@example.com:22\",command=\"echo \r\ntest\" %s", aliceKeyAuth)},
				{name: "trailing_backslash_at_eof", content: fmt.Sprintf(`permitconnect="*@example.com:22" %s\`, aliceKeyAuth)},
				{name: "backslash_space_before_newline", content: fmt.Sprintf("permitconnect=\"*@example.com:22\" \\ \n%s", aliceKeyAuth)},
				{name: "line_continuation_at_eof_without_key", content: `permitconnect="*@example.com:22" \`},
				// Pipe edge cases
				{name: "pipe_without_options", content: fmt.Sprintf(`%s | %s`, aliceKeyAuth, bobKeyAuth)},
				{name: "options_on_non_first_pipe_segment", content: fmt.Sprintf(`permitconnect="*@example.com:22" %s | permitconnect="*@other.com:22" %s`, aliceKeyAuth, bobKeyAuth)},
				{name: "invalid_key_in_pipe_segment", content: fmt.Sprintf(`permitconnect="*@example.com:22" %s | invalid`, aliceKeyAuth)},
				{name: "invalid_key_in_middle_pipe_segment", content: fmt.Sprintf(`permitconnect="*@example.com:22" %s | invalid | %s`, aliceKeyAuth, bobKeyAuth)},
				// Macro edge cases
				{
					name: "define_without_whitespace_separator",
					content: `
					#defineX SERVER_GROUP value
					permitconnect="*@example.com:22" SERVER_GROUP
					`,
				},
				{
					name: "macro_name_leading_digit",
					content: fmt.Sprintf(`
					#define ALICE_KEY %s
					#define 1BAD_KEY %s
					permitconnect="*@example.com:22" 1BAD_KEY
					`, aliceKeyAuth, bobKeyAuth),
				},
				{
					name: "macro_name_non_ascii",
					content: fmt.Sprintf(`
					#define ALICE_KEY %s
					#define BÄD_KEY %s
					permitconnect="*@example.com:22" BÄD_KEY
					`, aliceKeyAuth, bobKeyAuth),
				},
				{
					name: "self_referential_macro",
					content: fmt.Sprintf(`
					#define ALICE_KEY %s
					#define SELF_REFERENCE SELF_REFERENCE
					permitconnect="*@example.com:22" SELF_REFERENCE
					`, aliceKeyAuth),
				},
				{
					name: "self_referential_macro_in_quoted_value",
					content: fmt.Sprintf(`
					#define ALICE_KEY %s
					#define SELF_REFERENCE SELF_REFERENCE
					permitconnect="SELF_REFERENCE" ALICE_KEY
					`, aliceKeyAuth),
				},
				{
					name: "mutually_recursive_macros",
					content: `
					#define RECURSIVE_A RECURSIVE_B
					#define RECURSIVE_B RECURSIVE_A
					permitconnect="*@example.com:22" RECURSIVE_A
					`,
				},
				{
					name: "macro_recursion_exceeding_depth",
					content: fmt.Sprintf(`
					#define ALICE_KEY %s
					#define DEPTH_0 DEPTH_1
					#define DEPTH_1 DEPTH_2
					#define DEPTH_2 DEPTH_3
					#define DEPTH_3 DEPTH_4
					#define DEPTH_4 DEPTH_5
					#define DEPTH_5 DEPTH_6
					#define DEPTH_6 DEPTH_7
					#define DEPTH_7 DEPTH_8
					#define DEPTH_8 DEPTH_9
					#define DEPTH_9 ALICE_KEY
					permitconnect="*@example.com:22" DEPTH_0
					`, aliceKeyAuth),
				},
				{
					name:    "braced_macro_reference_leading_digit",
					content: fmt.Sprintf(`permitconnect="{{1BAD}}" %s`, aliceKeyAuth),
				},
				{
					name:    "braced_macro_unclosed",
					content: fmt.Sprintf(`permitconnect="{{BROKEN_NAME}" %s`, aliceKeyAuth),
				},
				{
					name:    "define_at_eof",
					content: "#define",
				},
				{
					name: "define_with_unterminated_quote",
					content: fmt.Sprintf(`
					#define BROKEN_QUOTE "unterminated
					permitconnect="BROKEN_QUOTE" %s
					`, aliceKeyAuth),
				},
				// Null byte cases
				{name: "null_byte_only", content: "\x00"},
				{name: "null_byte_in_key_data", content: "permitconnect=\"*@example.com:22\" ssh-ed25519 AAAA\x00AAAA comment"},
				{name: "null_byte_in_quoted_value", content: fmt.Sprintf("permitconnect=\"*@example.com:22\",command=\"a\x00b\" %s", aliceKeyAuth)},
			}

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					db, warnings, err := ParseFile([]byte(tt.content))
					if err != nil {
						t.Fatalf("ParseFile returned error: %v", err)
					}
					if len(warnings) == 0 {
						t.Error("expected warnings, got none")
					}
					if len(db) != 0 {
						t.Errorf("expected empty db, got %d keys", len(db))
					}
				})
			}
		})

		t.Run("warnings", func(t *testing.T) {
			db, warnings, err := ParseFile([]byte(fmt.Sprintf("permitconnect=\"invalid\" %s\n", aliceKeyAuth)))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(warnings) == 0 {
				t.Error("expected warnings, got none")
			}
			if len(db) != 0 {
				t.Errorf("expected 0 keys, got %d", len(db))
			}
		})
	})

	t.Run("parse_line", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			line := []byte(`permitconnect="*@example.com:22" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA alice`)
			opts, pubKey, err := ParseLine(line)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if pubKey == nil {
				t.Fatal("expected public key, got nil")
			}
			if len(opts.PermitConnects) != 1 {
				t.Errorf("expected 1 PermitConnect, got %d", len(opts.PermitConnects))
			}
			if opts.Comment != "alice" {
				t.Errorf("Comment = %q, want %q", opts.Comment, "alice")
			}
		})

		t.Run("missing_options", func(t *testing.T) {
			line := []byte(`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA alice`)
			_, _, err := ParseLine(line)
			if err == nil {
				t.Error("expected error, got nil")
				return
			}
			if !strings.Contains(err.Error(), "missing options") {
				t.Errorf("expected error containing %q, got %q", "missing options", err.Error())
			}
		})
	})

	t.Run("parse_key", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			line := []byte(`permitconnect="*@example.com:22" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA alice`)
			pubKey, comment, opts, err := ParseKey(line)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if pubKey == nil {
				t.Fatal("expected public key, got nil")
			}
			if comment != "alice" {
				t.Errorf("comment = %q, want %q", comment, "alice")
			}
			if len(opts) == 0 {
				t.Error("expected options, got none")
			}
		})

		t.Run("bare_key", func(t *testing.T) {
			line := []byte(`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA alice`)
			pubKey, _, opts, err := ParseKey(line)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if pubKey == nil {
				t.Fatal("expected public key, got nil")
			}
			if len(opts) != 0 {
				t.Errorf("expected no options, got %d", len(opts))
			}
		})

		t.Run("invalid", func(t *testing.T) {
			_, _, _, err := ParseKey([]byte("not-a-valid-key"))
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	})

	t.Run("parse_options", func(t *testing.T) {
		t.Run("missing_permitconnect", func(t *testing.T) {
			_, err := ParseOptions([]string{`command="ls"`})
			if err == nil {
				t.Error("expected error, got nil")
				return
			}
			if !strings.Contains(err.Error(), "permitconnect") {
				t.Errorf("expected error about permitconnect, got %q", err.Error())
			}
		})

		t.Run("default_permit_opens", func(t *testing.T) {
			opts, err := ParseOptions([]string{`permitconnect="*@example.com:22"`})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(opts.PermitOpens) != 3 {
				t.Errorf("expected 3 default PermitOpens, got %d", len(opts.PermitOpens))
			}
		})

		t.Run("malformed_option", func(t *testing.T) {
			_, err := ParseOptions([]string{`command=unquoted`})
			if err == nil {
				t.Error("expected error, got nil")
				return
			}
			if !strings.Contains(err.Error(), "malformed") {
				t.Errorf("expected error containing %q, got %q", "malformed", err.Error())
			}
		})

		t.Run("unknown_option", func(t *testing.T) {
			_, err := ParseOptions([]string{`permitconnect="*@example.com:22"`, `unknown`})
			if err == nil {
				t.Error("expected error, got nil")
				return
			}
			if !strings.Contains(err.Error(), "unknown option") {
				t.Errorf("expected error containing %q, got %q", "unknown option", err.Error())
			}
		})

		t.Run("restrict", func(t *testing.T) {
			opts, err := ParseOptions([]string{"restrict", `permitconnect="*@example.com:22"`})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !opts.NoPortForwarding || !opts.NoSocketForwarding || !opts.NoPty {
				t.Errorf("expected restrict to set all restrictions, got no-port-forwarding=%t no-socket-forwarding=%t no-pty=%t",
					opts.NoPortForwarding, opts.NoSocketForwarding, opts.NoPty)
			}
		})

		t.Run("restrict_with_overrides", func(t *testing.T) {
			opts, err := ParseOptions([]string{"restrict", "pty", "port-forwarding", `permitconnect="*@example.com:22"`})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if opts.NoPortForwarding || !opts.NoSocketForwarding || opts.NoPty {
				t.Errorf("expected pty and port-forwarding to override restrict, got no-port-forwarding=%t no-socket-forwarding=%t no-pty=%t",
					opts.NoPortForwarding, opts.NoSocketForwarding, opts.NoPty)
			}
		})
	})

	t.Run("split_option", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			tests := []struct {
				name      string
				input     string
				wantName  string
				wantValue string
			}{
				{name: "no_value", input: "restrict", wantName: "restrict"},
				{name: "empty_value", input: `command=""`, wantName: "command", wantValue: ""},
				{name: "simple_value", input: `command="ls"`, wantName: "command", wantValue: "ls"},
				{name: "escaped_quote", input: `command="echo \"hello\""`, wantName: "command", wantValue: `echo "hello"`},
				{name: "backslash_no_quote", input: `command="C:\\path"`, wantName: "command", wantValue: `C:\\path`},
			}

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					name, value, ok := SplitOption(tt.input)
					if !ok {
						t.Fatal("expected ok, got false")
					}
					if name != tt.wantName {
						t.Errorf("name = %q, want %q", name, tt.wantName)
					}
					if value != tt.wantValue {
						t.Errorf("value = %q, want %q", value, tt.wantValue)
					}
				})
			}
		})

		t.Run("invalid", func(t *testing.T) {
			tests := []struct {
				name  string
				input string
			}{
				{name: "unquoted_value", input: "command=ls"},
				{name: "missing_close_quote", input: `command="ls`},
				{name: "garbage_after_quote", input: `command="ls"extra`},
			}

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					_, _, ok := SplitOption(tt.input)
					if ok {
						t.Error("expected ok = false")
					}
				})
			}
		})
	})

	t.Run("quote_option_value", func(t *testing.T) {
		tests := []struct {
			name  string
			input string
			want  string
		}{
			{name: "simple", input: "hello", want: `"hello"`},
			{name: "empty", input: "", want: `""`},
			{name: "with_quote", input: `say "hi"`, want: `"say \"hi\""`},
			{name: "with_backslash", input: `C:\path`, want: `"C:\path"`},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got := QuoteOptionValue(tt.input)
				if got != tt.want {
					t.Errorf("got %q, want %q", got, tt.want)
				}
			})
		}
	})

	t.Run("parse_permit_connect", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			tests := []struct {
				name     string
				input    string
				wantUser string
				wantHost string
				wantPort string
			}{
				{name: "at_hostname", input: "root@example.com", wantUser: "root", wantHost: "example.com", wantPort: "22"},
				{name: "at_hostname_with_port", input: "root@example.com:2222", wantUser: "root", wantHost: "example.com", wantPort: "2222"},
				{name: "at_uppercase_host", input: "root@EXAMPLE.COM", wantUser: "root", wantHost: "example.com", wantPort: "22"},
				{name: "at_uppercase_host_with_port", input: "root@EXAMPLE.COM:2222", wantUser: "root", wantHost: "example.com", wantPort: "2222"},
				{name: "at_ipv4", input: "root@192.168.1.1", wantUser: "root", wantHost: "192.168.1.1", wantPort: "22"},
				{name: "at_ipv4_with_port", input: "root@192.168.1.1:2222", wantUser: "root", wantHost: "192.168.1.1", wantPort: "2222"},
				{name: "at_ipv4_cidr", input: "root@192.168.0.0/16", wantUser: "root", wantHost: "192.168.0.0/16", wantPort: "22"},
				{name: "at_ipv4_cidr_with_port", input: "root@192.168.0.0/16:2222", wantUser: "root", wantHost: "192.168.0.0/16", wantPort: "2222"},
				{name: "at_ipv6", input: "root@[2001:db8::1]", wantUser: "root", wantHost: "2001:db8::1", wantPort: "22"},
				{name: "at_ipv6_with_port", input: "root@[2001:db8::1]:2222", wantUser: "root", wantHost: "2001:db8::1", wantPort: "2222"},
				{name: "at_ipv6_bare", input: "root@2001:db8::1", wantUser: "root", wantHost: "2001:db8::1", wantPort: "22"},
				{name: "at_ipv6_normalized", input: "root@[2001:0db8::1]", wantUser: "root", wantHost: "2001:db8::1", wantPort: "22"},
				{name: "at_ipv6_normalized_with_port", input: "root@[2001:0db8::1]:2222", wantUser: "root", wantHost: "2001:db8::1", wantPort: "2222"},
				{name: "at_ipv6_cidr", input: "root@[2001:db8::/64]", wantUser: "root", wantHost: "2001:db8::/64", wantPort: "22"},
				{name: "at_ipv6_cidr_with_port", input: "root@[2001:db8::/64]:2222", wantUser: "root", wantHost: "2001:db8::/64", wantPort: "2222"},
				{name: "at_glob_all", input: "*@*:*", wantUser: "*", wantHost: "*", wantPort: "*"},
				{name: "at_glob_host", input: "alice@*.internal", wantUser: "alice", wantHost: "*.internal", wantPort: "22"},
				{name: "at_port_range", input: "alice@host:8000-8999", wantUser: "alice", wantHost: "host", wantPort: "8000-8999"},
				{name: "at_port_wildcard", input: "alice@host:*", wantUser: "alice", wantHost: "host", wantPort: "*"},
				{name: "at_user_with_at", input: "alice@corp@host", wantUser: "alice@corp", wantHost: "host", wantPort: "22"},
				{name: "plus_hostname", input: "root+example.com", wantUser: "root", wantHost: "example.com", wantPort: "22"},
				{name: "plus_hostname_with_port", input: "root+example.com+2222", wantUser: "root", wantHost: "example.com", wantPort: "2222"},
				{name: "plus_uppercase_host", input: "root+EXAMPLE.COM", wantUser: "root", wantHost: "example.com", wantPort: "22"},
				{name: "plus_uppercase_host_with_port", input: "root+EXAMPLE.COM+2222", wantUser: "root", wantHost: "example.com", wantPort: "2222"},
				{name: "plus_ipv4", input: "root+192.168.1.1", wantUser: "root", wantHost: "192.168.1.1", wantPort: "22"},
				{name: "plus_ipv4_with_port", input: "root+192.168.1.1+2222", wantUser: "root", wantHost: "192.168.1.1", wantPort: "2222"},
				{name: "plus_ipv4_cidr", input: "root+192.168.0.0/16", wantUser: "root", wantHost: "192.168.0.0/16", wantPort: "22"},
				{name: "plus_ipv4_cidr_with_port", input: "root+192.168.0.0/16+2222", wantUser: "root", wantHost: "192.168.0.0/16", wantPort: "2222"},
				{name: "plus_ipv6", input: "root+[2001:db8::1]", wantUser: "root", wantHost: "2001:db8::1", wantPort: "22"},
				{name: "plus_ipv6_with_port", input: "root+[2001:db8::1]+2222", wantUser: "root", wantHost: "2001:db8::1", wantPort: "2222"},
				{name: "plus_ipv6_bare", input: "root+2001:db8::1", wantUser: "root", wantHost: "2001:db8::1", wantPort: "22"},
				{name: "plus_ipv6_bare_with_port", input: "root+2001:db8::1+2222", wantUser: "root", wantHost: "2001:db8::1", wantPort: "2222"},
				{name: "plus_ipv6_normalized", input: "root+[2001:0db8::1]", wantUser: "root", wantHost: "2001:db8::1", wantPort: "22"},
				{name: "plus_ipv6_normalized_with_port", input: "root+[2001:0db8::1]+2222", wantUser: "root", wantHost: "2001:db8::1", wantPort: "2222"},
				{name: "plus_ipv6_cidr", input: "root+[2001:db8::/64]", wantUser: "root", wantHost: "2001:db8::/64", wantPort: "22"},
				{name: "plus_ipv6_cidr_with_port", input: "root+[2001:db8::/64]+2222", wantUser: "root", wantHost: "2001:db8::/64", wantPort: "2222"},
				{name: "plus_glob_all", input: "*+*+*", wantUser: "*", wantHost: "*", wantPort: "*"},
				{name: "plus_glob_host", input: "alice+*.internal", wantUser: "alice", wantHost: "*.internal", wantPort: "22"},
				{name: "plus_port_range", input: "alice+host+8000-8999", wantUser: "alice", wantHost: "host", wantPort: "8000-8999"},
				{name: "plus_port_wildcard", input: "alice+host+*", wantUser: "alice", wantHost: "host", wantPort: "*"},
			}

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					pc, err := ParsePermitConnect(tt.input)
					if err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
					if pc.User != tt.wantUser {
						t.Errorf("User = %q, want %q", pc.User, tt.wantUser)
					}
					if pc.Host != tt.wantHost {
						t.Errorf("Host = %q, want %q", pc.Host, tt.wantHost)
					}
					if pc.Port != tt.wantPort {
						t.Errorf("Port = %q, want %q", pc.Port, tt.wantPort)
					}
				})
			}
		})

		t.Run("invalid", func(t *testing.T) {
			tests := []struct {
				name  string
				input string
			}{
				{name: "empty", input: ""},
				{name: "no_user", input: "example.com:22"},
				{name: "too_long", input: "*@" + strings.Repeat("a", MaxPermitConnectLength) + ":22"},
				{name: "at_empty_user", input: "@example.com:22"},
				{name: "at_empty_host", input: "root@:22"},
				{name: "at_empty_brackets", input: "root@[]"},
				{name: "at_empty_brackets_with_port", input: "root@[]:22"},
				{name: "at_empty_port", input: "root@host:"},
				{name: "plus_empty_user", input: "+example.com+22"},
				{name: "plus_empty_host", input: "root++22"},
				{name: "plus_empty_brackets", input: "root+[]"},
				{name: "plus_empty_brackets_with_port", input: "root+[]+22"},
				{name: "plus_empty_port", input: "root+host+"},
				{name: "plus_too_many_parts", input: "a+b+c+d"},
			}

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					_, err := ParsePermitConnect(tt.input)
					if err == nil {
						t.Error("expected error, got nil")
					}
				})
			}
		})
	})

	t.Run("parse_permit_tcp", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			tests := []struct {
				name     string
				input    string
				wantHost string
				wantPort string
			}{
				{name: "host_port", input: "localhost:8080", wantHost: "localhost", wantPort: "8080"},
				{name: "wildcard", input: "*:443", wantHost: "*", wantPort: "443"},
				{name: "ipv6", input: "[::1]:22", wantHost: "::1", wantPort: "22"},
				{name: "port_range", input: "*:1-65535", wantHost: "*", wantPort: "1-65535"},
			}

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					pt, err := ParsePermitTCP(tt.input)
					if err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
					if pt.Host != tt.wantHost {
						t.Errorf("Host = %q, want %q", pt.Host, tt.wantHost)
					}
					if pt.Port != tt.wantPort {
						t.Errorf("Port = %q, want %q", pt.Port, tt.wantPort)
					}
				})
			}
		})

		t.Run("invalid", func(t *testing.T) {
			tests := []struct {
				name  string
				input string
				errSS string
			}{
				{name: "empty", input: "", errSS: "empty"},
				{name: "no_port", input: "localhost", errSS: "expected"},
				{name: "too_long", input: strings.Repeat("a", MaxPermitTCPLength+1) + ":22", errSS: "maximum length"},
			}

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					_, err := ParsePermitTCP(tt.input)
					if err == nil {
						t.Error("expected error, got nil")
						return
					}
					if !strings.Contains(err.Error(), tt.errSS) {
						t.Errorf("expected error containing %q, got %q", tt.errSS, err.Error())
					}
				})
			}
		})
	})

	t.Run("parse_permit_socket", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			tests := []struct {
				name     string
				input    string
				wantPath string
			}{
				{name: "wildcard", input: "*", wantPath: "*"},
				{name: "absolute_path", input: "/tmp/test.sock", wantPath: "/tmp/test.sock"},
				{name: "path_cleaned", input: "/tmp/../tmp/test.sock", wantPath: "/tmp/test.sock"},
			}

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					ps, err := ParsePermitSocket(tt.input)
					if err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
					if ps.Path != tt.wantPath {
						t.Errorf("Path = %q, want %q", ps.Path, tt.wantPath)
					}
				})
			}
		})

		t.Run("invalid", func(t *testing.T) {
			tests := []struct {
				name  string
				input string
				errSS string
			}{
				{name: "empty", input: "", errSS: "empty"},
				{name: "too_long", input: "/" + strings.Repeat("a", MaxPermitSocketLength), errSS: "maximum length"},
			}

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					_, err := ParsePermitSocket(tt.input)
					if err == nil {
						t.Error("expected error, got nil")
						return
					}
					if !strings.Contains(err.Error(), tt.errSS) {
						t.Errorf("expected error containing %q, got %q", tt.errSS, err.Error())
					}
				})
			}
		})
	})

	t.Run("parse_environment", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			tests := []struct {
				name      string
				input     string
				wantSign  string
				wantName  string
				wantValue string
			}{
				{name: "key_value", input: "FOO=bar", wantName: "FOO", wantValue: "bar"},
				{name: "empty_value", input: "FOO=", wantName: "FOO", wantValue: ""},
				{name: "underscore_name", input: "MY_VAR=1", wantName: "MY_VAR", wantValue: "1"},
				{name: "allow_pattern", input: "+TERM*", wantSign: "+", wantName: "TERM*"},
				{name: "deny_pattern", input: "-SECRET*", wantSign: "-", wantName: "SECRET*"},
				{name: "question_mark_pattern", input: "+VAR?", wantSign: "+", wantName: "VAR?"},
				{name: "bracket_pattern", input: "+VAR[AB]", wantSign: "+", wantName: "VAR[AB]"},
			}

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					env, err := ParseEnvironment(tt.input)
					if err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
					if env.Sign != tt.wantSign {
						t.Errorf("Sign = %q, want %q", env.Sign, tt.wantSign)
					}
					if env.Name != tt.wantName {
						t.Errorf("Name = %q, want %q", env.Name, tt.wantName)
					}
					if env.Value != tt.wantValue {
						t.Errorf("Value = %q, want %q", env.Value, tt.wantValue)
					}
				})
			}
		})

		t.Run("invalid", func(t *testing.T) {
			tests := []struct {
				name  string
				input string
				errSS string
			}{
				{name: "no_equals", input: "FOO", errSS: "expected NAME=value"},
				{name: "empty_name", input: "=bar", errSS: "expected NAME=value"},
				{name: "disallowed_char_in_name", input: "FOO-BAR=baz", errSS: "disallowed"},
				{name: "empty_allow_pattern", input: "+", errSS: "empty pattern"},
				{name: "empty_deny_pattern", input: "-", errSS: "empty pattern"},
				{name: "disallowed_char_in_pattern", input: "+FOO/BAR", errSS: "disallowed"},
			}

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					_, err := ParseEnvironment(tt.input)
					if err == nil {
						t.Error("expected error, got nil")
						return
					}
					if !strings.Contains(err.Error(), tt.errSS) {
						t.Errorf("expected error containing %q, got %q", tt.errSS, err.Error())
					}
				})
			}
		})
	})

	t.Run("parse_from", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			from, err := ParseFrom("192.168.1.0/24")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if from != "192.168.1.0/24" {
				t.Errorf("got %q, want %q", from, "192.168.1.0/24")
			}
		})

		t.Run("empty", func(t *testing.T) {
			_, err := ParseFrom("")
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	})

	t.Run("parse_timespec", func(t *testing.T) {
		t.Run("valid", func(t *testing.T) {
			tests := []struct {
				name  string
				input string
				want  time.Time
			}{
				{name: "date_only", input: "20250101", want: time.Date(2025, 1, 1, 0, 0, 0, 0, time.Local)},
				{name: "date_time_min", input: "202501011430", want: time.Date(2025, 1, 1, 14, 30, 0, 0, time.Local)},
				{name: "date_time_sec", input: "20250101143045", want: time.Date(2025, 1, 1, 14, 30, 45, 0, time.Local)},
				{name: "utc_date", input: "20250101Z", want: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)},
				{name: "utc_datetime", input: "202501011430Z", want: time.Date(2025, 1, 1, 14, 30, 0, 0, time.UTC)},
				{name: "utc_datetime_sec", input: "20250101143045Z", want: time.Date(2025, 1, 1, 14, 30, 45, 0, time.UTC)},
				{name: "utc_lowercase_z", input: "20250101z", want: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)},
			}

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					got, err := ParseTimespec(tt.input)
					if err != nil {
						t.Fatalf("unexpected error: %v", err)
					}
					if !got.Equal(tt.want) {
						t.Errorf("got %v, want %v", got, tt.want)
					}
				})
			}
		})

		t.Run("invalid", func(t *testing.T) {
			tests := []struct {
				name  string
				input string
				errSS string
			}{
				{name: "empty", input: "", errSS: "empty"},
				{name: "wrong_length", input: "2025", errSS: "invalid timespec length"},
				{name: "invalid_month_0", input: "20250001", errSS: "invalid month"},
				{name: "invalid_month_13", input: "20251301", errSS: "invalid month"},
				{name: "invalid_day_0", input: "20250100", errSS: "invalid day"},
				{name: "invalid_day_32", input: "20250132", errSS: "invalid day"},
				{name: "invalid_hour", input: "202501012400", errSS: "invalid hour"},
				{name: "invalid_minute", input: "202501011260", errSS: "invalid minute"},
				{name: "invalid_second", input: "20250101120060", errSS: "invalid second"},
				{name: "nonexistent_date", input: "20250230", errSS: "does not exist"},
			}

			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					_, err := ParseTimespec(tt.input)
					if err == nil {
						t.Error("expected error, got nil")
						return
					}
					if !strings.Contains(err.Error(), tt.errSS) {
						t.Errorf("expected error containing %q, got %q", tt.errSS, err.Error())
					}
				})
			}
		})
	})
}
