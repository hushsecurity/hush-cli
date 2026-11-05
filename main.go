package main

import (
	"flag"
	"fmt"
	"os"
)

var version = "dev" // set at build time

const usage = `Usage: hush <command> [flags]

Commands:
  login          Sign in to Hush in your browser
  logout         Forget the saved sign-in
  status         Show who you're signed in as
  skills list    List the skills assigned to you
  skills show    Show a skill and its SKILL.md
  skills sync    Install your skills into your agents' skills folders
  version        Print the version

Run "hush <command> -h" for a command's flags.
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Print(usage)
		return nil
	}
	cmd, args := args[0], args[1:]
	if cmd == "skills" && len(args) > 0 {
		cmd, args = "skills "+args[0], args[1:]
	}
	switch cmd {
	case "login":
		fs := flag.NewFlagSet("login", flag.ExitOnError)
		api := fs.String("api", "", "Hush API URL (default "+defaultAPI+", or $HUSH_API_URL)")
		org := fs.String("org", "", "your organization's short name, to skip choosing it")
		_ = fs.Parse(args)
		return login(*api, *org)
	case "logout":
		return logout()
	case "status":
		return status()
	case "skills list":
		fs := flag.NewFlagSet("skills list", flag.ExitOnError)
		asJSON := fs.Bool("json", false, "print JSON")
		_ = fs.Parse(args)
		return listSkills(*asJSON)
	case "skills show":
		if len(args) != 1 {
			return fmt.Errorf("usage: hush skills show <name>")
		}
		return showSkill(args[0])
	case "skills sync":
		fs := flag.NewFlagSet("skills sync", flag.ExitOnError)
		skill := fs.String("skill", "", "sync only this skill")
		_ = fs.Parse(args)
		return syncSkills(*skill)
	case "version", "--version":
		fmt.Println(version)
		return nil
	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil
	}
	return fmt.Errorf("unknown command %q\n\n%s", cmd, usage)
}
