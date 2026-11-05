package main

import "fmt"

func status() error {
	var s Session
	if err := load(sessionFile, &s); err != nil {
		return err
	}
	if s.RefreshToken == "" {
		fmt.Println(`Not signed in. Run "hush login".`)
		return nil
	}
	c, err := signedIn()
	if err != nil {
		return err
	}
	claims := c.claims()
	user := fmt.Sprint(claims["email"])
	if name, ok := claims["name"].(string); ok && name != "" {
		user = fmt.Sprintf("%s <%s>", name, user)
	}
	orgName := fmt.Sprint(claims["oid"])
	if s.Org != "" {
		orgName = fmt.Sprintf("%s (%s)", s.Org, orgName)
	}
	m, err := loadManifest()
	if err != nil {
		return err
	}
	fmt.Printf("Signed in to %s\n  user: %s (%v)\n  org:  %s\n  skills installed: %d\n",
		c.api, user, claims["sub"], orgName, len(m.Installed))
	return nil
}
