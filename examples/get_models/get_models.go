package main

import (
	"fmt"
	"os"

	"github.com/zeozeozeo/aihorde-go"
)

// Constants for standalone execution
const hordeURLModels = "https://aihorde.net/api"

func getenv(key, fallback string) string {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	return v
}

func main() {
	fmt.Println("\n--- Example: Get Active Models ---")
	apiKey := getenv("AIHORDE_API_KEY", "0000000000")

	horde := aihorde.NewAIHorde(
		aihorde.WithDefaultToken(apiKey),
		aihorde.WithAPIRoute(hordeURLModels),
		aihorde.WithClientAgent("GoExampleClient:1.0:github.com/zeozeozeo/aihorde-go"),
	)

	models, err := horde.GetModels(
		aihorde.WithModelsType(aihorde.ModelTypeImage),   // Filter for image models
		aihorde.WithModelsState(aihorde.ModelStateKnown), // Only show known models
	)
	if err != nil {
		fmt.Println("Error getting models:", err)
		return
	}
	fmt.Printf("Active Known Image Models (%d):\n", len(models))
	limit := 10 // Show a few more models
	if len(models) < limit {
		limit = len(models)
	}
	for _, model := range models[:limit] {
		fmt.Printf("  - %s (Count: %d, Queued: %.0f MPS, ETA: %ds)\n", model.Name, model.Count, model.Queued, model.ETA)
	}
	if len(models) > limit {
		fmt.Printf("  ... and %d more\n", len(models)-limit)
	}
}

// To run this example individually: go run examples/get_models.go
