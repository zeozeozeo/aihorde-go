package main

import (
	"fmt"
	"os"
	"time"

	"github.com/zeozeozeo/aihorde-go"
)

func getenv(key, fallback string) string {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	return v
}

func main() {
	apiKey := getenv("AIHORDE_API_KEY", "0000000000")

	horde := aihorde.NewAIHorde(
		aihorde.WithDefaultToken(apiKey),
		// Optional: Use a specific Client-Agent
		// aihorde.WithClientAgent("MyClientName:1.0:MyContactInfo"),
	)

	// Define image generation input
	input := aihorde.GenerationInputStable{
		Prompt: "A futuristic cityscape at night, cinematic lighting, high detail",
		Params: &aihorde.ModelGenerationInputStable{
			// Initialize embedded structs explicitly to set nested fields
			ModelPayloadRootStable: aihorde.ModelPayloadRootStable{
				ModelPayloadStyleStable: aihorde.ModelPayloadStyleStable{
					SamplerName: aihorde.SamplerKEulerA,
					PostProcessing: []aihorde.ModelGenerationInputPostProcessingType{
						aihorde.PostProcessingGFPGAN,
					},
					CfgScale: ptr(7.5),
					Width:    ptr(512),
					Height:   ptr(512),
					// Other ModelPayloadStyleStable fields can be set here
				},
				// Other ModelPayloadRootStable fields can be set here (e.g., Seed)
				// Seed: "my_seed",
			},
			// Fields directly in ModelGenerationInputStable
			Steps: ptr(30),
			N:     ptr(1),
		},
		// Optional: Specify models
		// Models: []string{"stable_diffusion"},
	}

	// Submit async image generation request
	fmt.Println("Submitting generation request...")
	req, err := horde.PostAsyncImageGenerate(input, aihorde.WithPostAsyncImageGenerateToken(apiKey))
	if err != nil {
		// Check if it's an APIError
		if apiErr, ok := err.(*aihorde.APIError); ok {
			fmt.Printf("API Error submitting request: %s (Code: %s)\n", apiErr.ErrorMessage, apiErr.ErrorCode)
			if len(apiErr.Errors) > 0 {
				fmt.Println("Validation Errors:", apiErr.Errors)
			}
		} else {
			fmt.Println("Error submitting request:", err)
		}
		return
	}
	fmt.Println("Generation Request ID:", req.ID)
	fmt.Printf("Estimated Kudos Cost: %.2f\n", req.Kudos)
	if len(req.Warnings) > 0 {
		fmt.Println("Warnings:", req.Warnings)
	}

	// Poll for the status until done
	fmt.Println("Waiting for generation to complete...")
	requestID := req.ID
	for {
		statusCheck, err := horde.GetAsyncGenerationCheck(requestID)
		if err != nil {
			fmt.Println("Error checking status:", err)
			// Optional: Implement retry logic or break
			time.Sleep(10 * time.Second) // Wait before retrying
			continue
		}

		fmt.Printf("  Status: Waiting: %d, Processing: %d, Restarted: %d, Finished: %d, Done: %t, Faulted: %t\n",
			statusCheck.Waiting, statusCheck.Processing, statusCheck.Restarted, statusCheck.Finished, statusCheck.Done, statusCheck.Faulted)

		if statusCheck.Done || statusCheck.Faulted {
			break
		}

		// Wait before checking again
		waitTime := max(time.Duration(statusCheck.WaitTime+5) * time.Second, 10 * time.Second)
		fmt.Printf("  Waiting %v before next check...\n", waitTime)
		time.Sleep(waitTime)
	}

	// Retrieve the final status with image data
	fmt.Println("Retrieving final status and image data...")
	finalStatus, err := horde.GetAsyncImageStatus(requestID)
	if err != nil {
		fmt.Println("Error retrieving final status:", err)
		return
	}

	if finalStatus.Faulted {
		fmt.Println("Generation faulted.")
		return
	}

	if len(finalStatus.Generations) > 0 {
		fmt.Println("Generation Complete!")
		for i, gen := range finalStatus.Generations {
			fmt.Printf("  Image %d:\n", i+1)
			fmt.Printf("    Worker: %s (%s)\n", gen.WorkerName, gen.WorkerID)
			fmt.Printf("    Model: %s\n", gen.Model)
			fmt.Printf("    Seed: %s\n", gen.Seed)
			fmt.Printf("    ID: %s\n", gen.ID)
			fmt.Printf("    Censored: %t\n", gen.Censored) // Or derive from metadata
			fmt.Printf("    State: %s\n", gen.State)
			fmt.Printf("    Image Data/URL: %s\n", gen.Img) // This will be base64 or an R2 URL
			if len(gen.GenMetadata) > 0 {
				fmt.Println("    Metadata:", gen.GenMetadata)
			}
		}
	} else {
		fmt.Println("Generation finished, but no images were returned.")
	}
}

func ptr[T any](v T) *T {
	return &v
}
