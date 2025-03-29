package main

import (
	"fmt"
	"os"

	"github.com/zeozeozeo/aihorde-go"
)

// Constants can be shared if examples are run together,
// but defined here for standalone execution.
const hordeURLPerf = "https://aihorde.net/api"

func getenv(key, fallback string) string {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	return v
}

func main() {
	fmt.Println("\n--- Example: Get Horde Performance ---")
	apiKey := getenv("AIHORDE_API_KEY", "0000000000")

	horde := aihorde.NewAIHorde(
		aihorde.WithDefaultToken(apiKey),
		aihorde.WithAPIRoute(hordeURLPerf),
		aihorde.WithClientAgent("GoExampleClient:1.0:github.com/zeozeozeo/aihorde-go"),
	)

	perf, err := horde.GetHordePerformance()
	if err != nil {
		fmt.Println("Error getting horde performance:", err)
		return
	}
	fmt.Printf("Horde Performance:\n")
	fmt.Printf("  Queued Image Requests: %d\n", perf.QueuedRequests)
	fmt.Printf("  Queued Text Requests: %d\n", perf.QueuedTextRequests)
	fmt.Printf("  Image Worker Count: %d\n", perf.WorkerCount)
	fmt.Printf("  Text Worker Count: %d\n", perf.TextWorkerCount)
	fmt.Printf("  Past Minute MPS: %.2f\n", perf.PastMinuteMegapixelsteps)
	fmt.Printf("  Queued Interrogations: %d\n", perf.QueuedForms)
	fmt.Printf("  Interrogator Count: %d\n", perf.InterrogatorCount)
}

// To run this example individually: go run examples/get_performance.go
