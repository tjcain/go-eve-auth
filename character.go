package main

import "fmt"

// CharacterInfo is a representation of select information returned from eve
// and discord Oauth
type CharacterInfo struct {
	ID        int    `json:"CharacterID"`
	Name      string `json:"CharacterName"`
	OwnerHash string `json:"CharacterOwnerHash"`

	// Discord details
	UserName      string `json:"username"`
	Discriminator int    `json:"discriminator"`
}

func (c CharacterInfo) cookieValue() string {
	return fmt.Sprintf("%d", c.ID)
}
