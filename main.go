package main

import (
	"fmt"
	"maps"
	"os"
	"os/signal"
	"slices"
	"syscall"

	"github.com/spf13/cobra"
)

var version = "dev" // set at build time

func main() {
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		if unlock != nil {
			unlock()
		}
		os.Exit(130)
	}()
	err := rootCmd().Execute()
	if unlock != nil {
		unlock()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "hush",
		Short:         "The Hush Security command line interface",
		Version:       version,
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
	loginCmd.Flags().StringVar(&api, "api", "", "Hush API URL (default "+defaultAPI+", or $HUSH_API_URL)")
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
			Run:   func(*cobra.Command, []string) { fmt.Println(version) },
		},
		skillsCmd(),
	)
	return root
}

func skillsCmd() *cobra.Command {
	skills := &cobra.Command{Use: "skills", Short: "Install the skills your organization assigned to you"}

	var asJSON bool
	list := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List your skills, and what's installed",
		Args:    cobra.NoArgs,
		RunE:    func(*cobra.Command, []string) error { return listSkills(asJSON) },
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
			return syncSkills("")
		},
	}
	sync.Flags().BoolVarP(&quiet, "quiet", "q", false, "print nothing but errors")

	skills.AddCommand(list, sync,
		&cobra.Command{
			Use:               "show <name>",
			Short:             "Show a skill and its SKILL.md",
			Args:              cobra.ExactArgs(1),
			ValidArgsFunction: completeSkills,
			RunE:              func(_ *cobra.Command, args []string) error { return showSkill(args[0]) },
		},
		&cobra.Command{
			Use:               "add <name>",
			Short:             "Install one skill (again, if you removed it)",
			Args:              cobra.ExactArgs(1),
			ValidArgsFunction: completeSkills,
			RunE:              func(_ *cobra.Command, args []string) error { return syncSkills(args[0]) },
		},
		&cobra.Command{
			Use:               "remove <name>",
			Aliases:           []string{"rm"},
			Short:             "Uninstall a skill, and keep sync from reinstalling it",
			Args:              cobra.ExactArgs(1),
			ValidArgsFunction: completeSkills,
			RunE:              func(_ *cobra.Command, args []string) error { return removeSkill(args[0]) },
		},
		&cobra.Command{
			Use:       "autosync [on|off]",
			Short:     "Sync your skills whenever Claude Code starts",
			Args:      cobra.MatchAll(cobra.MaximumNArgs(1), cobra.OnlyValidArgs),
			ValidArgs: []string{"on", "off"},
			RunE: func(_ *cobra.Command, args []string) error {
				return autosync(append(args, "")[0])
			},
		},
	)
	return skills
}

// completeSkills completes skill names from what's installed or removed
// locally, so pressing tab never waits on the network.
func completeSkills(_ *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
	m, err := loadManifest()
	if len(args) > 0 || err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	names := append(slices.Collect(maps.Keys(m.Installed)), m.Removed...)
	slices.Sort(names)
	return names, cobra.ShellCompDirectiveNoFileComp
}
