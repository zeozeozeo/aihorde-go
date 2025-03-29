package main

import (
	"fmt"
	"os"

	"github.com/zeozeozeo/aihorde-go"
)

// Replace with your actual API key
const hordeURL = "https://aihorde.net/api"

func getenv(key, fallback string) string {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	return v
}

func main() {
	fmt.Println("--- Example: Find User ---")
	apiKey := getenv("AIHORDE_API_KEY", "0000000000")

	horde := aihorde.NewAIHorde(
		aihorde.WithDefaultToken(apiKey),
		aihorde.WithAPIRoute(hordeURL),
		aihorde.WithClientAgent("GoExampleClient:1.0:github.com/zeozeozeo/aihorde-go"),
	)

	userDetails, err := horde.FindUser(aihorde.WithFindUserToken(apiKey)) // Use the key itself to find the user
	if err != nil {
		fmt.Println("Error finding user:", err)
		return
	}
	fmt.Printf("Found User: %s (ID: %d), Kudos: %.2f\n", userDetails.Username, userDetails.ID, userDetails.Kudos)
}
