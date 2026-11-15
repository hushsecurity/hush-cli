package cli

import (
	"fmt"

	"github.com/hushsecurity/hush-cli/internal/auth"
	"github.com/hushsecurity/hush-cli/internal/gateway"
	"github.com/hushsecurity/hush-cli/internal/skills"
)

func login(api, org string) error {
	if err := auth.Login(api, org); err != nil {
		return err
	}
	if m, err := skills.LoadManifest(); err == nil && len(m.Installed) == 0 {
		fmt.Println(`Run "hush skills sync" to install your skills.`)
	}
	return nil
}

func logout() error {
	if err := auth.Logout(); err != nil {
		return err
	}
	if err := gateway.ForgetAll(); err != nil {
		return err
	}
	fmt.Println("Signed out.")
	return nil
}

func status() error {
	s, err := auth.LoadSession()
	if err != nil {
		return err
	}
	if s.RefreshToken == "" {
		fmt.Println(`Not signed in. Run "hush login".`)
		return nil
	}
	c, err := auth.SignedIn()
	if err != nil {
		return err
	}
	claims := c.Claims()
	user := auth.UserName(claims)
	orgName := fmt.Sprint(claims["oid"])
	if s.Org != "" {
		orgName = fmt.Sprintf("%s (%s)", s.Org, orgName)
	}
	m, err := skills.LoadManifest()
	if err != nil {
		return err
	}
	fmt.Printf("Signed in to %s\n  user: %s (%v)\n  org:  %s\n  skills installed: %d\n",
		c.API(), user, claims["sub"], orgName, len(m.Installed))
	return nil
}
