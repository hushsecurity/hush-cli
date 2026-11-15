// Package cli is the hush command line.
package cli

import (
	"fmt"
	"maps"
	"os"
	"os/signal"
	"slices"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/hushsecurity/hush-cli/internal/auth"
	"github.com/hushsecurity/hush-cli/internal/config"
	"github.com/hushsecurity/hush-cli/internal/gateway"
	"github.com/hushsecurity/hush-cli/internal/skills"
	"github.com/hushsecurity/hush-cli/internal/version"
)

func Main() {
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		s := <-sig
		config.ReleaseLock()
		os.Exit(128 + int(s.(syscall.Signal))) // 130 for Ctrl-C, 143 for SIGTERM
	}()
	err := rootCmd().Execute()
	config.ReleaseLock()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "hush",
		Short:         "The Hush Security command line interface",
		Version:       version.Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	var api, org string
	loginCmd := &cobra.Command{
		Use:   "login",
		Short: "Sign in to Hush in your browser",
		Args:  cobra.NoArgs,
		RunE:  func(*cobra.Command, []string) error { return login(api, org) },
	}
	loginCmd.Flags().StringVar(&api, "api", "", "Hush API URL (default "+auth.DefaultAPI+", or $HUSH_API_URL)")
	loginCmd.Flags().StringVar(&org, "org", "", "your organization's short name, to skip choosing it")

	root.AddCommand(loginCmd,
		&cobra.Command{
			Use:   "logout",
			Short: "Forget the saved sign-in",
			Args:  cobra.NoArgs,
			RunE:  func(*cobra.Command, []string) error { return logout() },
		},
		&cobra.Command{
			Use:   "status",
			Short: "Show who you're signed in as",
			Args:  cobra.NoArgs,
			RunE:  func(*cobra.Command, []string) error { return status() },
		},
		&cobra.Command{
			Use:   "version",
			Short: "Print the version",
			Args:  cobra.NoArgs,
			Run:   func(*cobra.Command, []string) { fmt.Println(version.Version) },
		},
		skillsCmd(),
		gatewayCmd(),
	)
	return root
}

func gatewayCmd() *cobra.Command {
	gw := &cobra.Command{Use: "gateway", Aliases: []string{"gw"}, Short: "Connect your agents to a Hush gateway"}
	gw.AddCommand(&cobra.Command{
		Use:   "proxy <gateway-url>",
		Short: "Serve a gateway over stdio, for agents that run local MCP servers",
		Long: `Serve a gateway over stdio, for agents that run local MCP servers.

The connection is made from this device. Until you sign in to the gateway, the
first tool the agent calls opens your browser to sign in. Example, in an
agent's MCP config:

  "hush": {"command": "hush", "args": ["gateway", "proxy", "https://<gateway>/mcp"]}`,
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error { return gateway.Proxy(args[0]) },
	})

	var name string
	install := &cobra.Command{
		Use:   "install <client> <gateway-url>",
		Short: "Add a gateway to an agent on this device (supported: claude-desktop)",
		Long: `Add a gateway to an agent on this device, served by hush gateway proxy.

Supported clients: claude-desktop (its chat). It writes your Claude Desktop
config, so run it as yourself (not root), ideally while Claude Desktop is
closed, then open Claude Desktop.`,
		Example:           "  hush gateway install claude-desktop https://<gateway>/mcp",
		Args:              cobra.ExactArgs(2),
		ValidArgsFunction: completeClient,
		RunE: func(_ *cobra.Command, args []string) error {
			return gateway.Install(args[0], args[1], name)
		},
	}
	install.Flags().StringVar(&name, "name", "hush", "the server's name in the client")
	uninstall := &cobra.Command{
		Use:               "uninstall <client>",
		Short:             "Remove a gateway that install added",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeClient,
		RunE:              func(_ *cobra.Command, args []string) error { return gateway.Uninstall(args[0], name) },
	}
	uninstall.Flags().StringVar(&name, "name", "hush", "the server's name in the client")
	gw.AddCommand(install, uninstall)
	return gw
}

func completeClient(_ *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return gateway.Clients, cobra.ShellCompDirectiveNoFileComp
}

func skillsCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "skills", Short: "Install the skills your organization assigned to you"}

	var asJSON bool
	list := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List your skills, and what's installed",
		Args:    cobra.NoArgs,
		RunE:    func(*cobra.Command, []string) error { return skills.List(asJSON) },
	}
	list.Flags().BoolVar(&asJSON, "json", false, "print JSON")

	var quiet bool
	sync := &cobra.Command{
		Use:   "sync",
		Short: "Install your skills for your agents, and keep them current",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			if quiet {
				os.Stdout, _ = os.OpenFile(os.DevNull, os.O_WRONLY, 0) // errors go to stderr
			}
			return skills.Sync("")
		},
	}
	sync.Flags().BoolVarP(&quiet, "quiet", "q", false, "print nothing but errors")

	cmd.AddCommand(list, sync,
		&cobra.Command{
			Use:               "show <name>",
			Short:             "Show a skill and its SKILL.md",
			Args:              cobra.ExactArgs(1),
			ValidArgsFunction: completeSkills,
			RunE:              func(_ *cobra.Command, args []string) error { return skills.Show(args[0]) },
		},
		&cobra.Command{
			Use:               "add <name>",
			Short:             "Install one skill (again, if you removed it)",
			Args:              cobra.ExactArgs(1),
			ValidArgsFunction: completeSkills,
			RunE:              func(_ *cobra.Command, args []string) error { return skills.Sync(args[0]) },
		},
		&cobra.Command{
			Use:               "remove <name>",
			Aliases:           []string{"rm"},
			Short:             "Uninstall a skill, and keep sync from reinstalling it",
			Args:              cobra.ExactArgs(1),
			ValidArgsFunction: completeSkills,
			RunE:              func(_ *cobra.Command, args []string) error { return skills.Remove(args[0]) },
		},
		&cobra.Command{
			Use:       "autosync [on|off]",
			Short:     "Sync your skills whenever Claude Code starts",
			Args:      cobra.MatchAll(cobra.MaximumNArgs(1), cobra.OnlyValidArgs),
			ValidArgs: []string{"on", "off"},
			RunE: func(_ *cobra.Command, args []string) error {
				return skills.Autosync(append(args, "")[0])
			},
		},
	)
	return cmd
}

// completeSkills completes skill names from what's installed or removed
// locally, so pressing tab never waits on the network.
func completeSkills(_ *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
	m, err := skills.LoadManifest()
	if len(args) > 0 || err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	names := append(slices.Collect(maps.Keys(m.Installed)), m.Removed...)
	slices.Sort(names)
	return names, cobra.ShellCompDirectiveNoFileComp
}
