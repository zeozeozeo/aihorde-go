package main

import (
	"fmt"
	"os"
	"time"

	"github.com/zeozeozeo/aihorde-go"
)

// API key is needed for text generation
const hordeURLTextGen = "https://aihorde.net/api"

func getenv(key, fallback string) string {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	return v
}

func ptr[T any](v T) *T {
	return &v
}

func main() {
	fmt.Println("\n--- Example: Async Text Generation ---")
	apiKey := getenv("AIHORDE_API_KEY", "0000000000")

	horde := aihorde.NewAIHorde(
		aihorde.WithDefaultToken(apiKey),
		aihorde.WithAPIRoute(hordeURLTextGen),
		aihorde.WithClientAgent("GoExampleClient:1.0:github.com/zeozeozeo/aihorde-go"),
	)

	input := aihorde.GenerationInputKobold{
		Prompt: "Write a short story about a cat who dreams of being a lion.",
		Params: &aihorde.ModelGenerationInputKobold{
			ModelPayloadRootKobold: aihorde.ModelPayloadRootKobold{
				ModelPayloadStyleKobold: aihorde.ModelPayloadStyleKobold{
					Temperature: ptr(0.8),
					TopP:        ptr(0.95),
				},
			},
		},
		Models: []string{"KoboldAI/Fairytale-Storytelling-LoRA-v2"}, // Example model
	}

	fmt.Println("Submitting text generation request...")
	req, err := horde.PostAsyncTextGenerate(input, aihorde.WithPostAsyncTextGenerateToken(apiKey))
	if err != nil {
		fmt.Println("Error submitting text request:", err)
		return
	}
	fmt.Println("Text Generation Request ID:", req.ID)

	// --- Polling Logic ---
	requestID := req.ID
	for {
		statusCheck, err := horde.GetAsyncGenerationCheck(requestID) // Using same check endpoint
		if err != nil {
			fmt.Println("Error checking status:", err)
			time.Sleep(10 * time.Second)
			continue
		}
		fmt.Printf("  Status: Waiting: %d, Processing: %d, Finished: %d, Done: %t\n",
			statusCheck.Waiting, statusCheck.Processing, statusCheck.Finished, statusCheck.Done)
		if statusCheck.Done || statusCheck.Faulted {
			break
		}
		waitTime := time.Duration(statusCheck.WaitTime+5) * time.Second
		if waitTime < 10*time.Second {
			waitTime = 10 * time.Second
		}
		fmt.Printf("  Waiting %v before next check...\n", waitTime)
		time.Sleep(waitTime)
	}

	// --- Retrieve Final Status ---
	fmt.Println("Retrieving final text status...")
	finalStatus, err := horde.GetAsyncTextStatus(requestID)
	if err != nil {
		fmt.Println("Error retrieving final text status:", err)
		return
	}

	if finalStatus.Faulted {
		fmt.Println("Text generation faulted.")
		return
	}

	if len(finalStatus.Generations) > 0 {
		fmt.Println("Text Generation Complete!")
		for i, gen := range finalStatus.Generations {
			fmt.Printf("  Generation %d:\n", i+1)
			fmt.Printf("    Worker: %s (%s)\n", gen.WorkerName, gen.WorkerID)
			fmt.Printf("    Model: %s\n", gen.Model)
			fmt.Printf("    Text: %s\n", gen.Text)
		}
	} else {
		fmt.Println("Text generation finished, but no text was returned.")
	}
}

// To run this example individually: go run examples/async_text.go
