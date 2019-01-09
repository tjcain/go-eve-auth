package main

import "fmt"

// CharacterInfo is a representation of select information returned from
// https://login.eveonline.com/oauth/verify
type CharacterInfo struct {
	ID        int    `json:"CharacterID"`
	Name      string `json:"CharacterName"`
	OwnerHash string `json:"CharacterOwnerHash"`
}

func (c CharacterInfo) cookieValue() string {
	return fmt.Sprintf("%d", c.ID)
}
