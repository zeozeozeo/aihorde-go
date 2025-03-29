package aihorde

// ErrorMessages maps API error codes to human-readable messages.
var ErrorMessages = map[string]string{
	"MissingPrompt":                 "The generation prompt was not given",
	"CorruptPrompt":                 "The prompts was rejected as unethical",
	"KudosValidationError":          "Something went wrong when transferring kudos. This is a base rc, so you should never typically see it.",
	"NoValidActions":                "Something went wrong when modifying an entity on the horde. This is a base rc, so you should never typically see it.",
	"InvalidSize":                   "Requested image size is not a multiple of 64",
	"InvalidPromptSize":             "Prompt is too large",
	"TooManySteps":                  "Too many steps requested for image generation",
	"Profanity":                     "Profanity Detected. This is a base rc, so you should never typically see i",
	"ProfaneWorkerName":             "Profanity detected in worker name",
	"ProfaneBridgeAgent":            "Profanity detected in bridge agent",
	"ProfaneWorkerInfo":             "Profanity detected in worker info",
	"ProfaneUserName":               "Profanity detected in username",
	"ProfaneUserContact":            "Profanity detected in user contact details",
	"ProfaneAdminComment":           "Profanity detected in admin comment",
	"ProfaneTeamName":               "Profanity detected in team name",
	"ProfaneTeamInfo":               "Profanity detected in team info",
	"TooLong":                       "Provided string was too long. This is a base rc, so you should never typically see it.",
	"TooLongWorkerName":             "The provided worker name is too long",
	"TooLongUserName":               "The provided username is too long",
	"NameAlreadyExists":             "The provided name already exists. This is a base rc, so you should never typically see it.",
	"WorkerNameAlreadyExists":       "The provided worker name already exists",
	"TeamNameAlreadyExists":         "The provided team name already exists",
	"PolymorphicNameConflict":       "The provided worker name already exists for a different worker type (e.g. Dreamer VS Scribe)",
	"ImageValidationFailed":         "Source image validation failed unexpectedly",
	"SourceImageResolutionExceeded": "Source image resolution larger than the max allowed by the AI Horde",
	"SourceImageSizeExceeded":       "Source image file size larger than the max allowed by the AI Horde",
	"SourceImageUrlInvalid":         "Source image url does not contain an image",
	"SourceImageUnreadable":         "Source image could not be parsed",
	"InpaintingMissingMask":         "Missing mask or alpha channel for inpainting",
	"SourceMaskUnnecessary":         "Source mask sent without a source image",
	"UnsupportedSampler":            "Selected sampler unsupported with selected model",
	"UnsupportedModel":              "The required model name is unsupported with this payload. This is a base rc, so you should never typically see it.",
	"ControlNetUnsupported":         "ControlNet is unsupported in combination with this model",
	"ControlNetSourceMissing":       "Missing source image for ControlNet workflow",
	"ControlNetInvalidPayload":      "sent CN source and requested CN source at the same time",
	"SourceImageRequiredForModel":   "Source image is required for using this model",
	"UnexpectedModelName":           "Model name sent is not a Stable Diffusion checkpoint",
	"TooManyUpscalers":              "Tried to use more than 1 upscaler at a time",
	"ProcGenNotFound":               "The used generation for aesthetic ratings doesn't exist",
	"InvalidAestheticAttempt":       "Aesthetics rating attempt failed",
	"AestheticsNotCompleted":        "Attempted to rate non-completed request",
	"AestheticsNotPublic":           "Attempted to rate non-shared request",
	"AestheticsDuplicate":           "Sent duplicate images in an aesthetics set",
	"AestheticsMissing":             "Aesthetic ratings missing",
	"AestheticsSolo":                "Aesthetic ratings best-of contain a single image",
	"AestheticsConfused":            "The best image is not the one with the highest aesthetic rating",
	"AestheticsAlreadyExist":        "Aesthetic rating already submitted",
	"AestheticsServerRejected":      "Aesthetic server rejected submission",
	"AestheticsServerError":         "Aesthetic server returned error (provided)",
	"AestheticsServerDown":          "Aesthetic server is down",
	"AestheticsServerTimeout":       "Aesthetic server timed out during submission",
	"InvalidAPIKey":                 "Invalid AI Horde API key provided",
	"WrongCredentials":              "Provided user does not own this worker",
	"NotAdmin":                      "Request needs AI Horded admin credentials",
	"NotModerator":                  "Request needs AI Horded moderator credentials",
	"NotOwner":                      "Request needs worker owner credentials",
	"NotPrivileged":                 "This user is not hardcoded to perform this operation",
	"AnonForbidden":                 "Anonymous is not allowed to perform this operation",
	"AnonForbiddenWorker":           "Anonymous tried to run a worker",
	"AnonForbiddenUserMod":          "Anonymous tried to modify their user account",
	"NotTrusted":                    "Untrusted users are not allowed to perform this operation",
	"UntrustedTeamCreation":         "Untrusted user tried to create a team",
	"UntrustedUnsafeIP":             "Untrusted user tried to use a VPN for a worker",
	"WorkerMaintenance":             "Worker has been put into maintenance and cannot pop new jobs",
	"WorkerFlaggedMaintenance":      "Worker owner has been flagged and worker has been put into permanent maintenance",
	"TooManySameIPs":                "Same IP attempted to spawn too many workers",
	"WorkerInviteOnly":              "AI Horde is in worker invite-only mode and worker owner needs to request permission",
	"UnsafeIP":                      "Worker attempted to connect from VPN",
	"TimeoutIP":                     "Operation rejected because user IP in timeout",
	"TooManyNewIPs":                 "Too many workers from new IPs currently",
	"KudosUpfront":                  "This request requires upfront kudos to accept",
	"SharedKeyInvalid":              "Shared Key used in the request is invalid",
	"SharedKeyEmpty":                "Shared Key used in the request does not have any more kudos",
	"SharedKeyExpired":              "Shared Key used in the request has expired",
	"SharedKeyInsufficientKudos":    "Shared Key used in the request does not have enough kudos for this request",
	"SharedKeyAssignedStyles":       "Shared Key used in the request is assigned to styles and cannot be deleted",
	"InvalidJobID":                  "Job not found when trying to submit. This probably means its request was delected for inactivity",
	"RequestNotFound":               "Request not found. This probably means it was delected for inactivity",
	"WorkerNotFound":                "Worker ID not found",
	"TeamNotFound":                  "Team ID not found",
	"FilterNotFound":                "Regex filter not found",
	"UserNotFound":                  "User not found",
	"DuplicateGen":                  "Job has already been submitted",
	"AbortedGen":                    "Request aborted because too many jobs have failed",
	"RequestExpired":                "Request expired",
	"TooManyPrompts":                "User has requested too many generations concurrently",
	"NoValidWorkers":                "No workers online which can pick up this request",
	"MaintenanceMode":               "Request aborted because horde is in maintenance mode",
	"TargetAccountFlagged":          "Action rejected because target user has been flagged for violating Horde ToS",
	"SourceAccountFlagged":          "Action rejected because source user has been flagged for violating Horde ToS",
	"FaultWhenKudosReceiving":       "Unexpected error when receiving kudos",
	"FaultWhenKudosSending":         "Unexpected error when sending kudos",
	"TooFastKudosTransfers":         "User tried to send kudos too fast after receiving them from the same user",
	"KudosTransferToAnon":           "User tried to transfer kudos to Anon",
	"KudosTransferToSelf":           "User tried to transfer kudos to themselves",
	"KudosTransferNotEnough":        "User tried to transfer more kudos than they have",
	"NegativeKudosTransfer":         "User tried to transfer negative kudos",
	"KudosTransferFromAnon":         "User tried to transfer kudos using the Anon API key",
	"InvalidAwardUsername":          "Tried to award kudos to non-existing user",
	"KudosAwardToAnon":              "Tried to award kudos to Anonymous user",
	"NotAllowedAwards":              "This user is not allowed to Award Kudos",
	"NoWorkerModSelected":           "No valid worker modification selected",
	"NoUserModSelected":             "No valid user modification selected",
	"NoHordeModSelected":            "No valid horde modification selected",
	"NoTeamModSelected":             "No valid team modification selected",
	"NoFilterModSelected":           "No valid regex filter modification selected",
	"NoSharedKeyModSelected":        "No valid shared key modification selected",
	"BadRequest":                    "Generic HTTP 400 code. You should typically never see this",
	"Forbidden":                     "Generic HTTP 401 code. You should typically never see this",
	"Locked":                        "Generic HTTP code. You should typically never see this",
	"ControlNetMismatch":            "ControlNet type does not match the model",
	"HiResFixMismatch":              "HiResFix does not match the model",
	"TooManyLoras":                  "Too many loras requested",
	"BadLoraVersion":                "Bad lora version ID requested",
	"TooManyTIs":                    "Too many textual inversions requested",
	"BetaAnonForbidden":             "Anonymous user tried to use a beta feature",
	"BetaComparisonFault":           "Beta comparison fault",
	"BadCFGDecimals":                "CFG scale has too many decimal places",
	"BadCFGNumber":                  "CFG scale is not a valid number",
	"BadClientAgent":                "Client agent is not valid",
	"SpecialMissingPayload":         "Special payload is missing",
	"SpecialForbidden":              "Special payload is forbidden",
	"SpecialMissingUsername":        "Special payload is missing username",
	"SpecialModelNeedsSpecialUser":  "Special model needs special user",
	"SpecialFieldNeedsSpecialUser":  "Special field needs special user",
	"Img2ImgMismatch":               "Img2Img does not match the model",
	"TilingMismatch":                "Tiling does not match the model",
	"EducationCannotSendKudos":      "Education account cannot send kudos",
	"InvalidPriorityUsername":       "Invalid priority username",
	"OnlyServiceAccountProxy":       "Only service account can proxy requests",
	"RequiresTrust":                 "This feature requires trust",
	"InvalidRemixModel":             "Invalid remix model",
	"InvalidExtraSourceImages":      "Invalid extra source images",
	"TooManyExtraSourceImages":      "Too many extra source images",
	"MissingFullSamplerOrder":       "Missing full sampler order",
	"TooManyStopSequences":          "Too many stop sequences",
	"ExcessiveStopSequence":         "Excessive stop sequence length",
	"TokenOverflow":                 "Token overflow",
	"MoreThanMinExtraSourceImage":   "More than minimum extra source image",
	"InvalidExtraTexts":             "Invalid extra texts",
	"MissingExtraTexts":             "Missing extra texts",
	"InvalidTransparencyModel":      "Invalid transparency model",
	"InvalidTransparencyImg2Img":    "Invalid transparency img2img",
	"InvalidTransparencyCN":         "Invalid transparency controlnet",
	"HiResMismatch":                 "HiResFix does not match the model",
	"StylesAnonForbidden":           "Anonymous user tried to use styles",
	"StylePromptMissingVars":        "Style prompt is missing variables",
	"StylesRequiresCustomizer":      "Styles require customizer",
	"StyleMismatch":                 "Style does not match the model",
	"StyleGetMistmatch":             "Style get mismatch",
	"TooManyStyleExamples":          "Too many style examples",
	"ExampleURLAlreadyInUse":        "Example URL already in use",
	"MessagesOnlyOwnWorkers":        "Messages can only be sent to own workers",
	"Unknown":                       "Unknown rc code",
}

// ModelGenerationInputSampler defines the available samplers for image generation.
type ModelGenerationInputSampler string

const (
	SamplerKDPM2        ModelGenerationInputSampler = "k_dpm_2"
	SamplerKDPMFast     ModelGenerationInputSampler = "k_dpm_fast"
	SamplerLCM          ModelGenerationInputSampler = "lcm"
	SamplerKDPMpp2sA    ModelGenerationInputSampler = "k_dpmpp_2s_a"
	SamplerKHeun        ModelGenerationInputSampler = "k_heun"
	SamplerDDIM         ModelGenerationInputSampler = "DDIM"
	SamplerKLMS         ModelGenerationInputSampler = "k_lms"
	SamplerKDPMAdaptive ModelGenerationInputSampler = "k_dpm_adaptive"
	SamplerDPMSolver    ModelGenerationInputSampler = "dpmsolver"
	SamplerKDPMppSde    ModelGenerationInputSampler = "k_dpmpp_sde"
	SamplerKDPMpp2m     ModelGenerationInputSampler = "k_dpmpp_2m"
	SamplerKDPM2A       ModelGenerationInputSampler = "k_dpm_2_a"
	SamplerKEulerA      ModelGenerationInputSampler = "k_euler_a"
	SamplerKEuler       ModelGenerationInputSampler = "k_euler"
)

// SourceImageProcessingType defines how a source image should be processed.
type SourceImageProcessingType string

const (
	ProcessingImg2Img     SourceImageProcessingType = "img2img"
	ProcessingInpainting  SourceImageProcessingType = "inpainting"
	ProcessingOutpainting SourceImageProcessingType = "outpainting"
	ProcessingRemix       SourceImageProcessingType = "remix"
)

// ModelGenerationInputPostProcessingType defines available post-processing steps.
type ModelGenerationInputPostProcessingType string

const (
	PostProcessingGFPGAN                  ModelGenerationInputPostProcessingType = "GFPGAN"
	PostProcessingRealESRGANx4plus        ModelGenerationInputPostProcessingType = "RealESRGAN_x4plus"
	PostProcessingRealESRGANx2plus        ModelGenerationInputPostProcessingType = "RealESRGAN_x2plus"
	PostProcessingRealESRGANx4plusAnime6B ModelGenerationInputPostProcessingType = "RealESRGAN_x4plus_anime_6B"
	PostProcessingNMKDSiax                ModelGenerationInputPostProcessingType = "NMKD_Siax"
	PostProcessing4xAnimeSharp            ModelGenerationInputPostProcessingType = "4x_AnimeSharp"
	PostProcessingCodeFormers             ModelGenerationInputPostProcessingType = "CodeFormers"
	PostProcessingStripBackground         ModelGenerationInputPostProcessingType = "strip_background"
)

// ModelInterrogationFormType defines the types of image interrogation available.
type ModelInterrogationFormType string

const (
	InterrogationFormCaption                 ModelInterrogationFormType = "caption"
	InterrogationFormInterrogation           ModelInterrogationFormType = "interrogation"
	InterrogationFormNSFW                    ModelInterrogationFormType = "nsfw"
	InterrogationFormGFPGAN                  ModelInterrogationFormType = "GFPGAN"
	InterrogationFormRealESRGANx4plus        ModelInterrogationFormType = "RealESRGAN_x4plus"
	InterrogationFormRealESRGANx2plus        ModelInterrogationFormType = "RealESRGAN_x2plus"
	InterrogationFormRealESRGANx4plusAnime6B ModelInterrogationFormType = "RealESRGAN_x4plus_anime_6B"
	InterrogationFormNMKDSiax                ModelInterrogationFormType = "NMKD_Siax"
	InterrogationForm4xAnimeSharp            ModelInterrogationFormType = "4x_AnimeSharp"
	InterrogationFormCodeFormers             ModelInterrogationFormType = "CodeFormers"
	InterrogationFormStripBackground         ModelInterrogationFormType = "strip_background"
)

// ModelGenerationInputControlType defines the available ControlNet types.
type ModelGenerationInputControlType string

const (
	ControlTypeCanny         ModelGenerationInputControlType = "canny"
	ControlTypeHed           ModelGenerationInputControlType = "hed"
	ControlTypeDepth         ModelGenerationInputControlType = "depth"
	ControlTypeNormal        ModelGenerationInputControlType = "normal"
	ControlTypeOpenpose      ModelGenerationInputControlType = "openpose"
	ControlTypeSeg           ModelGenerationInputControlType = "seg"
	ControlTypeScribble      ModelGenerationInputControlType = "scribble"
	ControlTypeFakescribbles ModelGenerationInputControlType = "fakescribbles"
	ControlTypeHough         ModelGenerationInputControlType = "hough"
)

// ModelPayloadTextInversionInjectTarget defines where to inject a Textual Inversion trigger.
type ModelPayloadTextInversionInjectTarget string

const (
	InjectTIPrompt    ModelPayloadTextInversionInjectTarget = "prompt"
	InjectTINegPrompt ModelPayloadTextInversionInjectTarget = "negprompt"
)

// ModelGenerationInputWorkflow defines specific horde-engine workflows.
type ModelGenerationInputWorkflow string

const (
	WorkflowQRCode ModelGenerationInputWorkflow = "qr_code"
)

// RequestSingleWarningCode defines unique identifiers for API warnings.
type RequestSingleWarningCode string

const (
	WarningCodeNoAvailableWorker RequestSingleWarningCode = "NoAvailableWorker"
	WarningCodeClipSkipMismatch  RequestSingleWarningCode = "ClipSkipMismatch"
	WarningCodeStepsTooFew       RequestSingleWarningCode = "StepsTooFew"
	WarningCodeStepsTooMany      RequestSingleWarningCode = "StepsTooMany"
	WarningCodeCfgScaleMismatch  RequestSingleWarningCode = "CfgScaleMismatch"
	WarningCodeCfgScaleTooSmall  RequestSingleWarningCode = "CfgScaleTooSmall"
	WarningCodeCfgScaleTooLarge  RequestSingleWarningCode = "CfgScaleTooLarge"
	WarningCodeSamplerMismatch   RequestSingleWarningCode = "SamplerMismatch"
	WarningCodeSchedulerMismatch RequestSingleWarningCode = "SchedulerMismatch"
)

// GenerationMetadataType defines the relevance of a metadata field in generation results.
type GenerationMetadataType string

const (
	MetadataTypeLora              GenerationMetadataType = "lora"
	MetadataTypeTI                GenerationMetadataType = "ti"
	MetadataTypeCensorship        GenerationMetadataType = "censorship"
	MetadataTypeSourceImage       GenerationMetadataType = "source_image"
	MetadataTypeSourceMask        GenerationMetadataType = "source_mask"
	MetadataTypeExtraSourceImages GenerationMetadataType = "extra_source_images"
	MetadataTypeBatchIndex        GenerationMetadataType = "batch_index"
	MetadataTypeInformation       GenerationMetadataType = "information"
)

// GenerationMetadataValue defines the value of a metadata field in generation results.
type GenerationMetadataValue string

const (
	MetadataValueDownloadFailed   GenerationMetadataValue = "download_failed"
	MetadataValueParseFailed      GenerationMetadataValue = "parse_failed"
	MetadataValueBaselineMismatch GenerationMetadataValue = "baseline_mismatch"
	MetadataValueCSAM             GenerationMetadataValue = "csam"
	MetadataValueNSFW             GenerationMetadataValue = "nsfw"
	MetadataValueSeeRef           GenerationMetadataValue = "see_ref"
)

// GenerationState defines the state of a generated image or text.
type GenerationState string

const (
	GenStateOK       GenerationState = "ok"
	GenStateCensored GenerationState = "censored"
	GenStateFaulted  GenerationState = "faulted"
	GenStateCSAM     GenerationState = "csam" // Specific censorship type
)

// ModelType defines the type of model (image or text).
type ModelType string

const (
	ModelTypeImage ModelType = "image"
	ModelTypeText  ModelType = "text"
)

// ModelStateType defines the state filter for models.
type ModelStateType string

const (
	ModelStateKnown  ModelStateType = "known"
	ModelStateCustom ModelStateType = "custom"
	ModelStateAll    ModelStateType = "all"
)

// SortType defines sorting options for lists.
type SortType string

const (
	SortPopular SortType = "popular"
	SortAge     SortType = "age"
	SortKudos   SortType = "kudos" // For users list
)

// FilterValidityType defines validity filters for worker messages.
type FilterValidityType string

const (
	ValidityActive  FilterValidityType = "active"
	ValidityExpired FilterValidityType = "expired"
	ValidityAll     FilterValidityType = "all"
)

// DocumentFormat defines the format for documentation endpoints.
type DocumentFormat string

const (
	FormatHTML     DocumentFormat = "html"
	FormatMarkdown DocumentFormat = "markdown"
)

// RequestError represents a standard API error response.
type RequestError struct {
	// The error message for this status code.
	Message string `json:"message,omitempty"`
	// The return code for this error.
	RC string `json:"rc"`
}

// RequestValidationError represents an API error response with validation details.
type RequestValidationError struct {
	RequestError
	// The details of the validation error
	Errors map[string]string `json:"errors,omitempty"`
}

// RequestAsync represents the response after successfully queueing an asynchronous request.
type RequestAsync struct {
	// The UUID of the request. Use this to retrieve the request status in the future.
	ID string `json:"id,omitempty"`
	// The expected kudos consumption for this request.
	Kudos float64 `json:"kudos,omitempty"`
	// Any extra information from the horde about this request.
	Message string `json:"message,omitempty"`
	// Warnings associated with the request.
	Warnings []RequestSingleWarning `json:"warnings,omitempty"`
}

// RequestSingleWarning provides details about a specific warning.
type RequestSingleWarning struct {
	// A unique identifier for this warning.
	Code RequestSingleWarningCode `json:"code,omitempty"`
	// Something that you should be aware about this request, in plain text.
	Message string `json:"message,omitempty"`
}

// RequestStatusCheck provides the status of an asynchronous request without image data.
type RequestStatusCheck struct {
	// The amount of finished jobs in this request.
	Finished int `json:"finished,omitempty"`
	// The amount of still processing jobs in this request.
	Processing int `json:"processing,omitempty"`
	// The amount of jobs that timed out and had to be restarted or were reported as failed by a worker.
	Restarted int `json:"restarted,omitempty"`
	// The amount of jobs waiting to be picked up by a worker.
	Waiting int `json:"waiting,omitempty"`
	// True when all jobs in this request are done. Else False.
	Done bool `json:"done,omitempty"`
	// True when this request caused an internal server error and could not be completed.
	Faulted bool `json:"faulted,omitempty"`
	// The expected amount to wait (in seconds) to generate all jobs in this request.
	WaitTime int `json:"wait_time,omitempty"`
	// The position in the requests queue. This position is determined by relative Kudos amounts.
	QueuePosition int `json:"queue_position,omitempty"`
	// The amount of total Kudos this request has consumed until now.
	Kudos float64 `json:"kudos,omitempty"`
	// If False, this request will not be able to be completed with the pool of workers currently available.
	IsPossible bool `json:"is_possible,omitempty"`
}

// RequestStatusStable provides the full status of an asynchronous image generation request.
type RequestStatusStable struct {
	RequestStatusCheck
	// Generated images.
	Generations []GenerationStable `json:"generations,omitempty"`
	// If True, These images have been shared with LAION.
	Shared bool `json:"shared,omitempty"`
}

// RequestStatusKobold provides the full status of an asynchronous text generation request.
type RequestStatusKobold struct {
	RequestStatusCheck
	// Generated texts.
	Generations []GenerationKobold `json:"generations,omitempty"`
}

// Generation represents common fields for both image and text generations.
type Generation struct {
	// The UUID of the worker which generated this item.
	WorkerID string `json:"worker_id,omitempty"`
	// The name of the worker which generated this item.
	WorkerName string `json:"worker_name,omitempty"`
	// The model which generated this item.
	Model string `json:"model,omitempty"`
	// OBSOLETE (Use the gen_metadata field). The state of this generation.
	State GenerationState `json:"state,omitempty"` // Keep for potential backward compatibility if needed, but prefer gen_metadata
}

// GenerationStable represents a generated image result.
type GenerationStable struct {
	Generation
	// The generated image as a Base64-encoded .webp file or R2 link.
	Img string `json:"img,omitempty"`
	// The seed which generated this image.
	Seed string `json:"seed,omitempty"`
	// The ID for this image.
	ID string `json:"id,omitempty"`
	// When true this image has been censored by the worker's safety filter.
	Censored bool `json:"censored,omitempty"` // Can likely be derived from gen_metadata
	// Metadata about the generation process.
	GenMetadata []GenerationMetadataStable `json:"gen_metadata,omitempty"`
}

// GenerationKobold represents a generated text result.
type GenerationKobold struct {
	Generation
	// The generated text.
	Text string `json:"text,omitempty"`
	// The seed which generated this text.
	Seed int `json:"seed,omitempty"`
	// Metadata about the generation process.
	GenMetadata []GenerationMetadataKobold `json:"gen_metadata,omitempty"`
}

// GenerationMetadataStable provides metadata specific to image generation.
type GenerationMetadataStable struct {
	// The relevance of the metadata field
	Type GenerationMetadataType `json:"type"`
	// The value of the metadata field
	Value GenerationMetadataValue `json:"value"`
	// Optionally a reference for the metadata (e.g. a lora ID)
	Ref string `json:"ref,omitempty"`
}

// GenerationMetadataKobold provides metadata specific to text generation.
type GenerationMetadataKobold struct {
	// The relevance of the metadata field
	Type GenerationMetadataType `json:"type"`
	// The value of the metadata field
	Value GenerationMetadataValue `json:"value"`
	// Optionally a reference for the metadata (e.g. a lora ID)
	Ref string `json:"ref,omitempty"`
}

// UserDetails contains information about a specific user.
type UserDetails struct {
	// The user's unique Username. It is a combination of their chosen alias plus their ID.
	Username string `json:"username,omitempty"`
	// The user unique ID. It is always an integer.
	ID int `json:"id,omitempty"`
	// The amount of Kudos this user has. The amount of Kudos determines the priority when requesting image generations.
	Kudos float64 `json:"kudos,omitempty"`
	// (Privileged) The amount of Evaluating Kudos this untrusted user has from generations and uptime. When this number reaches a prespecified threshold, they automatically become trusted.
	EvaluatingKudos float64 `json:"evaluating_kudos,omitempty"`
	// How many concurrent generations this user may request.
	Concurrency int `json:"concurrency,omitempty"`
	// Whether this user has been invited to join a worker to the AI Horde and how many of them. When 0, this user cannot add (new) workers to the horde.
	WorkerInvited int `json:"worker_invited,omitempty"`
	// This user is a AI Horde moderator.
	Moderator    bool              `json:"moderator,omitempty"`
	KudosDetails *UserKudosDetails `json:"kudos_details,omitempty"`
	// How many workers this user has created (active or inactive).
	WorkerCount int `json:"worker_count,omitempty"`
	// Privileged or public when the user has explicitly allows it to be public.
	WorkerIDs []string `json:"worker_ids,omitempty"`
	// Styles created by the user.
	Styles []ResponseModelStylesUser `json:"styles,omitempty"`
	// (Privileged) The list of shared key IDs created by this user.
	SharedKeyIDs []string `json:"sharedkey_ids,omitempty"`
	// (Privileged) Active generation requests by this user.
	ActiveGenerations *UserActiveGenerations `json:"active_generations,omitempty"`
	MonthlyKudos      *MonthlyKudos          `json:"monthly_kudos,omitempty"`
	// This user is a trusted member of the AI Horde.
	Trusted bool `json:"trusted,omitempty"`
	// (Privileged) This user has been flagged for suspicious activity.
	Flagged bool `json:"flagged,omitempty"`
	// (Privileged) This user has been given the VPN role.
	VPN bool `json:"vpn,omitempty"`
	// This is a service account used by a horde proxy.
	Service bool `json:"service,omitempty"`
	// This is an education account used schools and universities.
	Education bool `json:"education,omitempty"`
	// When set to true, the user will be able to serve custom Stable Diffusion models which do not exist in the Official AI Horde Model Reference.
	Customizer bool `json:"customizer,omitempty"`
	// (Privileged) This user has been given the Special role.
	Special bool `json:"special,omitempty"`
	// (Privileged) How much suspicion this user has accumulated.
	Suspicious int `json:"suspicious,omitempty"`
	// If true, this user has not registered using an oauth service.
	Pseudonymous bool `json:"pseudonymous,omitempty"`
	// (Privileged) Contact details for the horde admins to reach the user in case of emergency.
	Contact string `json:"contact,omitempty"`
	// (Privileged) Information about this users by the admins
	AdminComment string `json:"admin_comment,omitempty"`
	// How many seconds since this account was created.
	AccountAge int `json:"account_age,omitempty"`
	// Deprecated: Use `Records.Usage` instead.
	Usage *UsageDetails `json:"usage,omitempty"`
	// Deprecated: Use `Records.Contribution` instead.
	Contributions *ContributionsDetails `json:"contributions,omitempty"`
	Records       *UserRecords          `json:"records,omitempty"`
}

// UserKudosDetails provides a breakdown of a user's kudos.
type UserKudosDetails struct {
	// The ammount of Kudos accumulated or used for generating images.
	Accumulated float64 `json:"accumulated,omitempty"`
	// The amount of Kudos this user has given to other users.
	Gifted float64 `json:"gifted,omitempty"`
	// The amount of Kudos this user has donated to public goods accounts like education.
	Donated float64 `json:"donated,omitempty"`
	// The amount of Kudos this user has been given by the AI Horde admins.
	Admin float64 `json:"admin,omitempty"`
	// The amount of Kudos this user has been given by other users.
	Received float64 `json:"received,omitempty"` // Note: Swagger has 'received', struct had 'Recieved'
	// The amount of Kudos this user has received from recurring rewards.
	Recurring float64 `json:"recurring,omitempty"`
	// The amount of Kudos this user has been awarded from things like rating images.
	Awarded float64 `json:"awarded,omitempty"`
	// The amount of Kudos this user has been awarded for styling other people's requests.
	Styled float64 `json:"styled,omitempty"`
}

// ResponseModelStylesUser provides short style info linked to a user.
type ResponseModelStylesUser struct {
	ResponseModelStylesShort
	// The style type, image or text
	Type ModelType `json:"type,omitempty"`
}

// UserActiveGenerations lists active generation IDs for a user.
type UserActiveGenerations struct {
	// (Privileged) The list of active text generation IDs requested by this user.
	Text []string `json:"text,omitempty"`
	// (Privileged) The list of active image generation IDs requested by this user.
	Image []string `json:"image,omitempty"`
	// (Privileged) The list of active alchemy generation IDs requested by this user.
	Alchemy []string `json:"alchemy,omitempty"` // Note: Alchemy not in provided spec paths
}

// MonthlyKudos details recurring kudos for a user.
type MonthlyKudos struct {
	// How much recurring Kudos this user receives monthly.
	Amount int `json:"amount,omitempty"`
	// Last date this user received monthly Kudos. (date-time)
	LastReceived string `json:"last_received,omitempty"`
}

// UsageDetails tracks user's generation requests.
type UsageDetails struct {
	// How many megapixelsteps this user has requested.
	Megapixelsteps float64 `json:"megapixelsteps,omitempty"`
	// How many images this user has requested.
	Requests int `json:"requests,omitempty"`
}

// ContributionsDetails tracks user's generation contributions.
type ContributionsDetails struct {
	// How many megapixelsteps this user has generated.
	Megapixelsteps float64 `json:"megapixelsteps,omitempty"`
	// How many images this user has generated.
	Fulfillments int `json:"fulfillments,omitempty"`
}

// UserRecords provides detailed usage and contribution records.
type UserRecords struct {
	Usage        *UserThingRecords  `json:"usage,omitempty"`
	Contribution *UserThingRecords  `json:"contribution,omitempty"`
	Fulfillment  *UserAmountRecords `json:"fulfillment,omitempty"`
	Request      *UserAmountRecords `json:"request,omitempty"`
	Style        *UserAmountRecords `json:"style,omitempty"`
}

// UserThingRecords tracks megapixelsteps and tokens.
type UserThingRecords struct {
	// How many megapixelsteps this user has generated or requested.
	Megapixelsteps float64 `json:"megapixelsteps,omitempty"`
	// How many token this user has generated or requested.
	Tokens int `json:"tokens,omitempty"`
}

// UserAmountRecords tracks counts for different generation types.
type UserAmountRecords struct {
	// How many images this user has generated, requested or styled.
	Image int `json:"image,omitempty"`
	// How many texts this user has generated, requested or styled.
	Text int `json:"text,omitempty"`
	// How many texts this user has generated or requested.
	Interrogation int `json:"interrogation,omitempty"`
}

// ModifyUserInput defines fields for modifying a user account (Admin only).
type ModifyUserInput struct {
	// The amount of kudos to modify (can be negative).
	Kudos *float64 `json:"kudos,omitempty"`
	// The amount of concurrent request this user can have.
	Concurrency *int `json:"concurrency,omitempty"` // Min: 0, Max: 500
	// The amount by which to multiply the users kudos consumption.
	UsageMultiplier *float64 `json:"usage_multiplier,omitempty"` // Min: 0.1, Max: 10
	// Set to the amount of workers this user is allowed to join to the horde when in worker invite-only mode.
	WorkerInvited *int `json:"worker_invited,omitempty"`
	// Set to true to make this user a horde moderator.
	Moderator *bool `json:"moderator,omitempty"`
	// Set to true to make this user display their worker IDs.
	PublicWorkers *bool `json:"public_workers,omitempty"`
	// When specified, will start assigning the user monthly kudos, starting now!
	MonthlyKudos *int `json:"monthly_kudos,omitempty"`
	// When specified, will change the username. No profanity allowed!
	Username *string `json:"username,omitempty"` // MinLen: 3, MaxLen: 100
	// When set to true,the user and their servers will not be affected by suspicion.
	Trusted *bool `json:"trusted,omitempty"`
	// When set to true, the user cannot tranfer kudos and all their workers are put into permanent maintenance.
	Flagged *bool `json:"flagged,omitempty"`
	// When set to true, the user will be able to serve custom Stable Diffusion models which do not exist in the Official AI Horde Model Reference.
	Customizer *bool `json:"customizer,omitempty"`
	// When set to true, the user will be able to onboard workers behind a VPN. This should be used as a temporary solution until the user is trusted.
	VPN *bool `json:"vpn,omitempty"`
	// When set to true, the user is considered a service account proxying the requests for other users.
	Service *bool `json:"service,omitempty"`
	// When set to true, the user is considered an education account and some options become more restrictive.
	Education *bool `json:"education,omitempty"`
	// When set to true, The user can send special payloads.
	Special *bool `json:"special,omitempty"`
	// When set to true, the replacement filter will always be applied against this user
	Filtered *bool `json:"filtered,omitempty"`
	// Set the user's suspicion back to 0.
	ResetSuspicion *bool `json:"reset_suspicion,omitempty"`
	// Contact details for the horde admins to reach the user in case of emergency. This is only visible to horde moderators.
	Contact *string `json:"contact,omitempty"` // MinLen: 5, MaxLen: 500
	// Add further information about this user for the other admins.
	AdminComment *string `json:"admin_comment,omitempty"` // MinLen: 5, MaxLen: 500
}

// ModifyUser represents the response after modifying a user account.
type ModifyUser struct {
	// The new total Kudos this user has after this request.
	NewKudos *float64 `json:"new_kudos,omitempty"`
	// The request concurrency this user has after this request.
	Concurrency *int `json:"concurrency,omitempty"`
	// Multiplies the amount of kudos lost when generating images.
	UsageMultiplier *float64 `json:"usage_multiplier,omitempty"`
	// Whether this user has been invited to join a worker to the horde and how many of them. When 0, this user cannot add (new) workers to the horde.
	WorkerInvited *int `json:"worker_invited,omitempty"`
	// The user's new moderator status.
	Moderator *bool `json:"moderator,omitempty"`
	// The user's new public_workers status.
	PublicWorkers *bool `json:"public_workers,omitempty"`
	// The user's new username.
	Username *string `json:"username,omitempty"`
	// The user's new monthly kudos total.
	MonthlyKudos *int `json:"monthly_kudos,omitempty"`
	// The user's new trusted status.
	Trusted *bool `json:"trusted,omitempty"`
	// The user's new flagged status.
	Flagged *bool `json:"flagged,omitempty"`
	// The user's new customizer status.
	Customizer *bool `json:"customizer,omitempty"`
	// The user's new vpn status.
	VPN *bool `json:"vpn,omitempty"`
	// The user's new service status.
	Service *bool `json:"service,omitempty"`
	// The user's new education status.
	Education *bool `json:"education,omitempty"`
	// The user's new special status.
	Special *bool `json:"special,omitempty"`
	// The user's new suspiciousness rating.
	NewSuspicion *int `json:"new_suspicion,omitempty"`
	// The new contact details.
	Contact *string `json:"contact,omitempty"`
	// The new admin comment.
	AdminComment *string `json:"admin_comment,omitempty"`
}

// ActiveModel provides details about an active model on the horde.
type ActiveModel struct {
	ActiveModelLite
	// The average speed of generation for this model.
	Performance float64 `json:"performance,omitempty"`
	// The amount waiting to be generated by this model (e.g., megapixelsteps).
	Queued float64 `json:"queued,omitempty"`
	// The job count waiting to be generated by this model.
	Jobs float64 `json:"jobs,omitempty"` // Note: Swagger says number, might be int?
	// Estimated time in seconds for this model's queue to be cleared.
	ETA int `json:"eta,omitempty"`
	// The model type (text or image).
	Type ModelType `json:"type,omitempty"`
}

// ActiveModelLite provides basic details about an active model.
type ActiveModelLite struct {
	// The Name of a model available by workers in this horde.
	Name string `json:"name,omitempty"`
	// How many of workers in this horde are running this model.
	Count int `json:"count,omitempty"`
}

// ModelDetails is currently underspecified in the provided `types.go`.
// Based on the Swagger, it should return an array of ActiveModel for the specific model.
// Let's redefine it as such.
type ModelDetails []ActiveModel

// GenerationInputStable defines the input for an image generation request.
type GenerationInputStable struct {
	// The prompt which will be sent to Stable Diffusion to generate an image.
	Prompt string `json:"prompt"`
	// Parameters for the generation model.
	Params *ModelGenerationInputStable `json:"params,omitempty"`
	// Set to true if this request is NSFW. This will skip workers which censor images.
	NSFW *bool `json:"nsfw,omitempty"` // Default: false
	// When true, only trusted workers will serve this request. When False, Evaluating workers will also be used which can increase speed but adds more risk!
	TrustedWorkers *bool `json:"trusted_workers,omitempty"` // Default: false
	// When true, only inference backends that are validated by the AI Horde devs will serve this request. When False, non-validated backends will also be used which can increase speed but you may end up with unexpected results.
	ValidatedBackends *bool `json:"validated_backends,omitempty"` // Default: true
	// When True, allows slower workers to pick up this request. Disabling this incurs an extra kudos cost.
	SlowWorkers *bool `json:"slow_workers,omitempty"` // Default: true
	// When True, allows very slower workers to pick up this request. Use this when you don't mind waiting a lot.
	ExtraSlowWorkers *bool `json:"extra_slow_workers,omitempty"` // Default: false
	// If the request is SFW, and the worker accidentally generates NSFW, it will send back a censored image.
	CensorNSFW *bool `json:"censor_nsfw,omitempty"` // Default: false
	// Specify up to 5 workers which are allowed to service this request.
	Workers []string `json:"workers,omitempty"`
	// If true, the worker list will be treated as a blacklist instead of a whitelist.
	WorkerBlacklist *bool `json:"worker_blacklist,omitempty"` // Default: false
	// Specify which models are allowed to be used for this request.
	Models []string `json:"models,omitempty"`
	// The Base64-encoded webp to use for img2img.
	SourceImage string `json:"source_image,omitempty"`
	// If source_image is provided, specifies how to process it.
	SourceProcessing SourceImageProcessingType `json:"source_processing,omitempty"` // Default: img2img
	// If source_processing is set to 'inpainting' or 'outpainting', this parameter can be optionally provided as the Base64-encoded webp mask of the areas to inpaint. If this arg is not passed, the inpainting/outpainting mask has to be embedded as alpha channel.
	SourceMask string `json:"source_mask,omitempty"`
	// Extra source images for processing.
	ExtraSourceImages []ExtraSourceImage `json:"extra_source_images,omitempty"`
	// If True, the image will be sent via cloudflare r2 download link.
	R2 *bool `json:"r2,omitempty"` // Default: true
	// If True, The image will be shared with LAION for improving their dataset. This will also reduce your kudos consumption by 2. For anonymous users, this is always True.
	Shared *bool `json:"shared,omitempty"` // Default: false
	// If enabled, suspicious prompts are sanitized through a string replacement filter instead.
	ReplacementFilter *bool `json:"replacement_filter,omitempty"` // Default: true
	// When true, the endpoint will simply return the cost of the request in kudos and exit.
	DryRun *bool `json:"dry_run,omitempty"` // Default: false
	// If using a service account as a proxy, provide this value to identify the actual account from which this request is coming from.
	ProxiedAccount string `json:"proxied_account,omitempty"`
	// When true, This request will not use batching. This will allow you to retrieve accurate seeds. Feature is restricted to Trusted users and Patreons.
	DisableBatching *bool `json:"disable_batching,omitempty"` // Default: false
	// When true and the request requires upfront kudos and the account does not have enough The request will be downgraded in steps and resolution so that it does not need upfront kudos.
	AllowDowngrade *bool `json:"allow_downgrade,omitempty"` // Default: false
	// Provide a URL where the AI Horde will send a POST call after each delivered generation.
	Webhook string `json:"webhook,omitempty"` // MinLen: 10, MaxLen: 1024
	// A horde style ID or name to use for this generation
	Style string `json:"style,omitempty"` // MinLen: 3, MaxLen: 1024
}

// ModelGenerationInputStable defines the core parameters for image generation models.
type ModelGenerationInputStable struct {
	ModelPayloadRootStable
	// The number of steps to use for generation.
	Steps *int `json:"steps,omitempty"` // Default: 30, Min: 1, Max: 500
	// The amount of images to generate.
	N *int `json:"n,omitempty"` // Default: 1, Min: 1, Max: 20
}

// ModelPayloadRootStable contains common root parameters for stable diffusion models.
type ModelPayloadRootStable struct {
	ModelPayloadStyleStable
	// The seed to use to generate this request. You can pass text as well as numbers.
	Seed string `json:"seed,omitempty"`
	// If passed with multiple n, the provided seed will be incremented every time by this value.
	SeedVariation *int `json:"seed_variation,omitempty"` // Min: 1, Max: 1000
	// The type of ControlNet to use.
	ControlType ModelGenerationInputControlType `json:"control_type,omitempty"`
	// Set to True if the image submitted is a pre-generated control map for ControlNet use.
	ImageIsControl *bool `json:"image_is_control,omitempty"` // Default: false
	// Set to True if you want the ControlNet map returned instead of a generated image.
	ReturnControlMap *bool `json:"return_control_map,omitempty"` // Default: false
	// Extra text inputs for specialized workflows.
	ExtraTexts []ExtraText `json:"extra_texts,omitempty"`
}

// ModelPayloadStyleStable contains style-related parameters for stable diffusion models.
type ModelPayloadStyleStable struct {
	// The sampler to use for generation.
	SamplerName ModelGenerationInputSampler `json:"sampler_name,omitempty"` // Default: k_euler_a
	// The Classifier-Free Guidance scale.
	CfgScale *float64 `json:"cfg_scale,omitempty"` // Default: 7.5, Min: 0, Max: 100
	// The denoising strength for img2img/remix.
	DenoisingStrength *float64 `json:"denoising_strength,omitempty"` // Min: 0.01, Max: 1.0
	// The denoising strength for hires fix.
	HiresFixDenoisingStrength *float64 `json:"hires_fix_denoising_strength,omitempty"` // Min: 0.01, Max: 1.0
	// The height of the image to generate.
	Height *int `json:"height,omitempty"` // Default: 512, Min: 64, Max: 3072, MultipleOf: 64
	// The width of the image to generate.
	Width *int `json:"width,omitempty"` // Default: 512, Min: 64, Max: 3072, MultipleOf: 64
	// The list of post-processors to apply to the image, in order.
	PostProcessing []ModelGenerationInputPostProcessingType `json:"post_processing,omitempty"`
	// Set to True to enable karras noise scheduling tweaks.
	Karras *bool `json:"karras,omitempty"` // Default: false
	// Set to True to create images that stitch together seamlessly.
	Tiling *bool `json:"tiling,omitempty"` // Default: false
	// Set to True to process the image at base resolution before upscaling and re-processing or to use Stable Cascade 2-pass.
	HiresFix *bool `json:"hires_fix,omitempty"` // Default: false
	// The number of CLIP language processor layers to skip.
	ClipSkip *int `json:"clip_skip,omitempty"` // Min: 1, Max: 12
	// The strength of the face fixer post-processor.
	FacefixerStrength *float64 `json:"facefixer_strength,omitempty"` // Min: 0, Max: 1.0
	// LoRAs to apply during generation.
	Loras []ModelPayloadLorasStable `json:"loras,omitempty"`
	// Textual Inversions to apply during generation.
	Tis []ModelPayloadTextualInversionsStable `json:"tis,omitempty"`
	// Special payload for specific model needs.
	Special map[string]interface{} `json:"special,omitempty"` // Note: Swagger defines as object with additionalProperties: object
	// Explicitly specify the horde-engine workflow to use.
	Workflow ModelGenerationInputWorkflow `json:"workflow,omitempty"`
	// Set to True to generate the image using Layer Diffuse, creating an image with a transparent background.
	Transparent *bool `json:"transparent,omitempty"` // Default: false
}

// ModelPayloadLorasStable defines parameters for applying a LoRA.
type ModelPayloadLorasStable struct {
	// The exact name or CivitAI Model Page ID of the LoRa. If is_version is true, this should be the CivitAI version ID.
	Name string `json:"name"` // MinLen: 1, MaxLen: 255
	// The strength of the LoRa to apply to the SD model.
	Model *float64 `json:"model,omitempty"` // Default: 1.0, Min: -5.0, Max: 5.0
	// The strength of the LoRa to apply to the clip model.
	Clip *float64 `json:"clip,omitempty"` // Default: 1.0, Min: -5.0, Max: 5.0
	// If set, will try to discover a trigger for this LoRa which matches or is similar to this string and inject it into the prompt. If 'any' is specified it will be pick the first trigger.
	InjectTrigger string `json:"inject_trigger,omitempty"` // MinLen: 1, MaxLen: 30
	// If true, will consider the LoRa ID as a CivitAI version ID and search accordingly. Ensure the name is an integer.
	IsVersion *bool `json:"is_version,omitempty"` // Default: false
}

// ModelPayloadTextualInversionsStable defines parameters for applying a Textual Inversion.
type ModelPayloadTextualInversionsStable struct {
	// The exact name or CivitAI ID of the Textual Inversion.
	Name string `json:"name"` // MinLen: 1, MaxLen: 255
	// If set, Will automatically add this TI filename to the prompt or negative prompt accordingly using the provided strength. If this is set to None, then the user will have to manually add the embed to the prompt themselves.
	InjectTi ModelPayloadTextInversionInjectTarget `json:"inject_ti,omitempty"`
	// The strength with which to apply the TI to the prompt. Only used when inject_ti is not None
	Strength *float64 `json:"strength,omitempty"` // Default: 1.0, Min: -5.0, Max: 5.0
}

// ExtraText defines additional text inputs for specific workflows.
type ExtraText struct {
	// The extra text to send along with this generation.
	Text string `json:"text,omitempty"` // MinLen: 1
	// The reference which points how and where this text should be used.
	Reference string `json:"reference,omitempty"` // MinLen: 3
}

// ExtraSourceImage defines an additional source image for processing.
type ExtraSourceImage struct {
	// The Base64-encoded webp to use for further processing.
	Image string `json:"image,omitempty"` // MinLen: 1
	// Optional field, determining the strength to use for the processing
	Strength *float64 `json:"strength,omitempty"` // Default: 1.0
}

// GenerationInputKobold defines the input for a text generation request.
type GenerationInputKobold struct {
	// The prompt which will be sent to KoboldAI to generate text.
	Prompt string `json:"prompt,omitempty"`
	// Parameters for the generation model.
	Params *ModelGenerationInputKobold `json:"params,omitempty"`
	// Specify which softpompt needs to be used to service this request.
	Softprompt string `json:"softprompt,omitempty"` // MinLen: 1
	// When true, only trusted workers will serve this request. When False, Evaluating workers will also be used which can increase speed but adds more risk!
	TrustedWorkers *bool `json:"trusted_workers,omitempty"` // Default: false
	// When true, only inference backends that are validated by the AI Horde devs will serve this request. When False, non-validated backends will also be used which can increase speed but you may end up with unexpected results.
	ValidatedBackends *bool `json:"validated_backends,omitempty"` // Default: true
	// When True, allows slower workers to pick up this request. Disabling this incurs an extra kudos cost.
	SlowWorkers *bool `json:"slow_workers,omitempty"` // Default: true
	// Specify up to 5 workers which are allowed to service this request.
	Workers []string `json:"workers,omitempty"`
	// If true, the worker list will be treated as a blacklist instead of a whitelist.
	WorkerBlacklist *bool `json:"worker_blacklist,omitempty"` // Default: false
	// Specify which models are allowed to be used for this request.
	Models []string `json:"models,omitempty"`
	// When true, the endpoint will simply return the cost of the request in kudos and exit.
	DryRun *bool `json:"dry_run,omitempty"` // Default: false
	// If using a service account as a proxy, provide this value to identify the actual account from which this request is coming from.
	ProxiedAccount string `json:"proxied_account,omitempty"`
	// Extra source images (e.g., for multimodal models).
	ExtraSourceImages []ExtraSourceImage `json:"extra_source_images,omitempty"`
	// When true, This request will not use batching. This will allow you to retrieve accurate seeds. Feature is restricted to Trusted users and Patreons.
	DisableBatching *bool `json:"disable_batching,omitempty"` // Default: false
	// When true and the request requires upfront kudos and the account does not have enough The request will be downgraded in max context and max tokens so that it does not need upfront kudos.
	AllowDowngrade *bool `json:"allow_downgrade,omitempty"` // Default: false
	// Provide a URL where the AI Horde will send a POST call after each delivered generation.
	Webhook string `json:"webhook,omitempty"`
	// A horde style ID or name to use for this generation
	Style string `json:"style,omitempty"` // MinLen: 3, MaxLen: 1024
	// When True, allows very slower workers to pick up this request. Use this when you don't mind waiting a lot.
	ExtraSlowWorkers *bool `json:"extra_slow_workers,omitempty"` // Default: false
}

// ModelGenerationInputKobold defines the core parameters for KoboldAI text generation models.
type ModelGenerationInputKobold struct {
	ModelPayloadRootKobold
	// Add specific fields if any (Swagger shows empty)
}

// ModelPayloadRootKobold contains common root parameters for KoboldAI models.
type ModelPayloadRootKobold struct {
	ModelPayloadStyleKobold
	// Number of generations to produce.
	N *int `json:"n,omitempty"` // Default: 1, Min: 1, Max: 20
	// Maximum number of tokens to send to the model.
	MaxContextLength *int `json:"max_context_length,omitempty"` // Default: 2048, Min: 80, Max: 1048576
	// Number of tokens to generate.
	MaxLength *int `json:"max_length,omitempty"` // Default: 80, Min: 16, Max: 1024
}

// ModelPayloadStyleKobold contains style-related parameters for KoboldAI models.
type ModelPayloadStyleKobold struct {
	// Input formatting option. When enabled, adds a leading space to your input if there is no trailing whitespace at the end of the previous action.
	Frmtadsnsp *bool `json:"frmtadsnsp,omitempty"` // Default: false
	// Output formatting option. When enabled, replaces all occurrences of two or more consecutive newlines in the output with one newline.
	Frmtrmblln *bool `json:"frmtrmblln,omitempty"` // Default: false
	// Output formatting option. When enabled, removes #/@%}{+=~|\\^<> from the output.
	Frmtrmspch *bool `json:"frmtrmspch,omitempty"` // Default: false
	// Output formatting option. When enabled, removes some characters from the end of the output such that the output doesn't end in the middle of a sentence. If the output is less than one sentence long, does nothing.
	Frmttriminc *bool `json:"frmttriminc,omitempty"` // Default: false
	// Base repetition penalty value.
	RepPen *float64 `json:"rep_pen,omitempty"` // Min: 1, Max: 3
	// Repetition penalty range.
	RepPenRange *int `json:"rep_pen_range,omitempty"` // Min: 0, Max: 4096
	// Repetition penalty slope.
	RepPenSlope *float64 `json:"rep_pen_slope,omitempty"` // Min: 0, Max: 10
	// Output formatting option. When enabled, removes everything after the first line of the output, including the newline.
	Singleline *bool `json:"singleline,omitempty"` // Default: false
	// Temperature value.
	Temperature *float64 `json:"temperature,omitempty"` // Min: 0, Max: 5.0
	// Tail free sampling value.
	Tfs *float64 `json:"tfs,omitempty"` // Min: 0.0, Max: 1.0
	// Top-a sampling value.
	TopA *float64 `json:"top_a,omitempty"` // Min: 0.0, Max: 1.0
	// Top-k sampling value.
	TopK *int `json:"top_k,omitempty"` // Min: 0, Max: 100
	// Top-p sampling value.
	TopP *float64 `json:"top_p,omitempty"` // Min: 0.001, Max: 1.0
	// Typical sampling value.
	Typical *float64 `json:"typical,omitempty"` // Min: 0.0, Max: 1.0
	// Array of integers representing the sampler order to be used.
	SamplerOrder []int `json:"sampler_order,omitempty"`
	// When True, uses the default KoboldAI bad word IDs.
	UseDefaultBadwordsids *bool `json:"use_default_badwordsids,omitempty"` // Default: true
	// An array of string sequences whereby the model will stop generating further tokens. The returned text WILL contain the stop sequence.
	StopSequence []string `json:"stop_sequence,omitempty"`
	// Min-p sampling value.
	MinP *float64 `json:"min_p,omitempty"` // Default: 0.0, Min: 0.0, Max: 1.0
	// Quadratic sampling value.
	SmoothingFactor *float64 `json:"smoothing_factor,omitempty"` // Default: 0.0, Min: 0.0, Max: 10.0
	// Dynamic temperature range value.
	DynatempRange *float64 `json:"dynatemp_range,omitempty"` // Default: 0.0, Min: 0.0, Max: 5.0
	// Dynamic temperature exponent value.
	DynatempExponent *float64 `json:"dynatemp_exponent,omitempty"` // Default: 1.0, Min: 0.0, Max: 5.0
}

// AestheticsPayload defines the input for submitting aesthetic ratings.
type AestheticsPayload struct {
	// The UUID of the best image in this generation batch (only used when 2+ images generated). If 2+ aesthetic ratings are also provided, then they take precedence if they're not tied.
	Best string `json:"best,omitempty"` // MinLen: 36, MaxLen: 36
	// Ratings for individual images in the batch.
	Ratings []AestheticRating `json:"ratings,omitempty"`
}

// AestheticRating defines a single aesthetic rating for an image.
type AestheticRating struct {
	// The UUID of image being rated.
	ID string `json:"id"` // MinLen: 36, MaxLen: 36
	// The aesthetic rating 1-10 for this image.
	Rating int `json:"rating"` // Min: 1, Max: 10
	// The artifacts rating for this image (0=flawless, 5=garbage).
	Artifacts *int `json:"artifacts,omitempty"` // Min: 0, Max: 5
}

// GenerationSubmitted represents the response after submitting a generation result or rating.
type GenerationSubmitted struct {
	// The amount of kudos gained for submitting this request.
	Reward float64 `json:"reward,omitempty"`
}

// PopInput defines common fields for popping generation requests.
type PopInput struct {
	// The Name of the Worker.
	Name string `json:"name,omitempty"`
	// Users with priority to use this worker.
	PriorityUsernames []string `json:"priority_usernames,omitempty"`
	// Whether this worker can generate NSFW requests or not.
	NSFW *bool `json:"nsfw,omitempty"` // Default: false
	// Which models this worker is serving.
	Models []string `json:"models,omitempty"` // Item MinLen: 3, MaxLen: 255
	// The worker name, version and website.
	BridgeAgent string `json:"bridge_agent,omitempty"` // Default: unknown:0:unknown, MaxLen: 1000
	// How many threads this worker is running.
	Threads *int `json:"threads,omitempty"` // Default: 1, Min: 1, Max: 50
	// If True, this worker will only pick up requests where the owner has the required kudos to consume already available.
	RequireUpfrontKudos *bool `json:"require_upfront_kudos,omitempty"` // Default: false
	// How many jobs to pop at the same time
	Amount *int `json:"amount,omitempty"` // Default: 1, Min: 1, Max: 20
	// If True, marks the worker as very slow.
	ExtraSlowWorker *bool `json:"extra_slow_worker,omitempty"` // Default: true
}

// PopInputStable defines fields for popping image generation requests.
type PopInputStable struct {
	PopInput
	// The maximum amount of pixels this worker can generate.
	MaxPixels *int `json:"max_pixels,omitempty"` // Default: 262144
	// Words which, when detected will refuse to pick up any jobs.
	Blacklist []string `json:"blacklist,omitempty"`
	// If True, this worker will pick up img2img requests.
	AllowImg2Img *bool `json:"allow_img2img,omitempty"` // Default: true
	// If True, this worker will pick up inpainting/outpainting requests.
	AllowPainting *bool `json:"allow_painting,omitempty"` // Default: true
	// If True, this worker will pick up img2img requests coming from clients with an unsafe IP.
	AllowUnsafeIPAddr *bool `json:"allow_unsafe_ipaddr,omitempty"` // Default: true
	// If True, this worker will pick up requests requesting post-processing.
	AllowPostProcessing *bool `json:"allow_post_processing,omitempty"` // Default: true
	// If True, this worker will pick up requests requesting ControlNet.
	AllowControlNet *bool `json:"allow_controlnet,omitempty"` // Default: true
	// If True, this worker will pick up requests requesting SDXL ControlNet.
	AllowSDXLControlNet *bool `json:"allow_sdxl_controlnet,omitempty"` // Default: true
	// If True, this worker will pick up requests requesting LoRas.
	AllowLora *bool `json:"allow_lora,omitempty"` // Default: true
	// If True, This worker will not pick up jobs with more steps than the average allowed for that model.
	LimitMaxSteps *bool `json:"limit_max_steps,omitempty"` // Default: true
}

// PopInputKobold defines fields for popping text generation requests.
type PopInputKobold struct {
	PopInput
	// The maximum amount of tokens this worker can generate.
	MaxLength *int `json:"max_length,omitempty"` // Default: 512
	// The max amount of context to submit to this AI for sampling.
	MaxContextLength *int `json:"max_context_length,omitempty"` // Default: 2048
	// The available softprompt files on this worker for the currently running model.
	Softprompts []string `json:"softprompts,omitempty"`
}

// GenerationPayloadStable represents the data payload sent to an image worker.
type GenerationPayloadStable struct {
	// The payload containing generation parameters.
	Payload *ModelPayloadStable `json:"payload,omitempty"`
	// The UUID for this image generation.
	ID string `json:"id,omitempty"`
	// The UUIDs for batched image generations.
	IDs []string `json:"ids,omitempty"`
	// Messages for the worker.
	Messages []ResponseModelMessagePop `json:"messages,omitempty"`
	// The amount of seconds before this job is considered stale and aborted.
	TTL int `json:"ttl,omitempty"`
	// Details about skipped requests.
	Skipped *NoValidRequestFoundStable `json:"skipped,omitempty"`
	// Which of the available models to use for this request.
	Model string `json:"model,omitempty"`
	// The Base64-encoded webp to use for img2img.
	SourceImage string `json:"source_image,omitempty"`
	// If source_image is provided, specifies how to process it.
	SourceProcessing SourceImageProcessingType `json:"source_processing,omitempty"`
	// If img_processing is set to 'inpainting' or 'outpainting', this parameter can be optionally provided as the mask.
	SourceMask string `json:"source_mask,omitempty"`
	// Extra source images for processing.
	ExtraSourceImages []ExtraSourceImage `json:"extra_source_images,omitempty"`
	// The r2 upload link to use to upload this image.
	R2Upload string `json:"r2_upload,omitempty"`
	// The r2 upload links for batched images.
	R2Uploads []string `json:"r2_uploads,omitempty"`
}

// GenerationPayloadKobold represents the data payload sent to a text worker.
type GenerationPayloadKobold struct {
	// The payload containing generation parameters.
	Payload *ModelPayloadKobold `json:"payload,omitempty"`
	// The UUID for this text generation.
	ID string `json:"id,omitempty"`
	// The UUIDs for batched text generations.
	IDs []string `json:"ids,omitempty"`
	// Messages for the worker.
	Messages []ResponseModelMessagePop `json:"messages,omitempty"`
	// The amount of seconds before this job is considered stale and aborted.
	TTL int `json:"ttl,omitempty"`
	// Extra source images (e.g., for multimodal models).
	ExtraSourceImages []ExtraSourceImage `json:"extra_source_images,omitempty"`
	// Details about skipped requests.
	Skipped *NoValidRequestFoundKobold `json:"skipped,omitempty"`
	// The soft prompt requested for this generation.
	Softprompt string `json:"softprompt,omitempty"`
	// Which of the available models to use for this request.
	Model string `json:"model,omitempty"`
}

// ModelPayloadStable defines the specific payload structure for image generation workers.
type ModelPayloadStable struct {
	ModelPayloadRootStable
	// The prompt which will be sent to Stable Diffusion to generate an image.
	Prompt string `json:"prompt,omitempty"`
	// Legacy steps parameter.
	DDIMSteps *int `json:"ddim_steps,omitempty"` // Default: 30
	// Legacy image count parameter.
	NIter *int `json:"n_iter,omitempty"` // Default: 1
	// When true will apply NSFW censoring model on the generation.
	UseNSFWCensor *bool `json:"use_nsfw_censor,omitempty"`
}

// ModelPayloadKobold defines the specific payload structure for text generation workers.
type ModelPayloadKobold struct {
	ModelPayloadRootKobold
	// The prompt which will be sent to KoboldAI to generate the text.
	Prompt string `json:"prompt,omitempty"`
}

// ResponseModelMessagePop represents a message popped by a worker.
type ResponseModelMessagePop struct {
	// The ID of this message
	ID string `json:"id"`
	// The message sent
	Message string `json:"message"`
	// The origin of this message. Typically this will be the horde moderators.
	Origin string `json:"origin,omitempty"`
	// The date at which this message will expire. (date-time)
	Expiry string `json:"expiry"`
}

// NoValidRequestFound provides reasons why a worker skipped requests.
type NoValidRequestFound struct {
	// How many waiting requests were skipped because they demanded a specific worker.
	WorkerID int `json:"worker_id,omitempty"`
	// How many waiting requests were skipped because they required higher performance.
	Performance int `json:"performance,omitempty"`
	// How many waiting requests were skipped because they demanded a nsfw generation which this worker does not provide.
	NSFW int `json:"nsfw,omitempty"`
	// How many waiting requests were skipped because they demanded a generation with a word that this worker does not accept.
	Blacklist int `json:"blacklist,omitempty"`
	// How many waiting requests were skipped because they demanded a trusted worker which this worker is not.
	Untrusted int `json:"untrusted,omitempty"`
	// How many waiting requests were skipped because they demanded a different model than what this worker provides.
	Models int `json:"models,omitempty"`
	// How many waiting requests were skipped because they require a higher version of the bridge than this worker is running.
	BridgeVersion int `json:"bridge_version,omitempty"`
	// How many waiting requests were skipped because the user didn't have enough kudos when this worker requires upfront kudos.
	Kudos int `json:"kudos,omitempty"`
}

// NoValidRequestFoundStable provides image-specific reasons why a worker skipped requests.
type NoValidRequestFoundStable struct {
	NoValidRequestFound
	// How many waiting requests were skipped because they demanded a higher size than this worker provides.
	MaxPixels int `json:"max_pixels,omitempty"`
	// How many waiting requests were skipped because they demanded a higher step count that the worker wants.
	StepCount int `json:"step_count,omitempty"`
	// How many waiting requests were skipped because they came from an unsafe IP.
	UnsafeIP int `json:"unsafe_ip,omitempty"`
	// How many waiting requests were skipped because they requested img2img.
	Img2Img int `json:"img2img,omitempty"`
	// How many waiting requests were skipped because they requested inpainting/outpainting.
	Painting int `json:"painting,omitempty"`
	// How many waiting requests were skipped because they requested post-processing.
	PostProcessing int `json:"post-processing,omitempty"` // Note hyphen
	// How many waiting requests were skipped because they requested loras.
	Lora int `json:"lora,omitempty"`
	// How many waiting requests were skipped because they requested a controlnet.
	ControlNet int `json:"controlnet,omitempty"`
}

// NoValidRequestFoundKobold provides text-specific reasons why a worker skipped requests.
type NoValidRequestFoundKobold struct {
	NoValidRequestFound
	// How many waiting requests were skipped because they demanded a higher max_context_length than what this worker provides.
	MaxContextLength int `json:"max_context_length,omitempty"`
	// How many waiting requests were skipped because they demanded more generated tokens that what this worker can provide.
	MaxLength int `json:"max_length,omitempty"`
	// How many waiting requests were skipped because they demanded an available soft-prompt which this worker does not have.
	MatchingSoftprompt int `json:"matching_softprompt,omitempty"`
}

// SubmitInput defines common fields for submitting generation results.
type SubmitInput struct {
	// The UUID of this generation.
	ID string `json:"id"`
	// R2 result was uploaded to R2, else the string of the result.
	Generation string `json:"generation,omitempty"` // Example: "R2"
	// The state of this generation.
	State GenerationState `json:"state,omitempty"` // Default: ok
}

// SubmitInputStable defines fields for submitting image generation results.
type SubmitInputStable struct {
	SubmitInput
	// The seed for this generation.
	Seed int `json:"seed"`
	// OBSOLETE (start using meta): If True, this resulting image has been censored.
	Censored *bool `json:"censored,omitempty"` // Default: false
	// Metadata about the generation process.
	GenMetadata []GenerationMetadataStable `json:"gen_metadata,omitempty"`
}

// SubmitInputKobold defines fields for submitting text generation results.
type SubmitInputKobold struct {
	SubmitInput
	// Metadata about the generation process.
	GenMetadata []GenerationMetadataKobold `json:"gen_metadata,omitempty"`
}

// SimpleResponse represents a basic success response with a message.
type SimpleResponse struct {
	// The result of this operation.
	Message string `json:"message"` // Default: "OK"
}

// KudosTransferred represents the response after transferring kudos.
type KudosTransferred struct {
	// The amount of Kudos tranferred.
	Transferred float64 `json:"transferred,omitempty"`
}

// KudosAwarded represents the response after awarding kudos.
type KudosAwarded struct {
	// The amount of Kudos awarded.
	Awarded float64 `json:"awarded,omitempty"`
}

// HordeModes represents the current operational modes of the horde.
type HordeModes struct {
	// When True, this horde will not accept new requests for image generation, but will finish processing the ones currently in the queue.
	MaintenanceMode bool `json:"maintenance_mode,omitempty"`
	// When True, this horde will not only accept worker explicitly invited to join.
	InviteOnlyMode bool `json:"invite_only_mode,omitempty"`
	// When True, this horde will not always provide full information in order to throw off attackers.
	RaidMode bool `json:"raid_mode,omitempty"`
}

// HordePerformance provides performance statistics for the horde.
type HordePerformance struct {
	// The amount of waiting and processing image requests currently in this horde.
	QueuedRequests int `json:"queued_requests,omitempty"`
	// The amount of waiting and processing text requests currently in this horde.
	QueuedTextRequests int `json:"queued_text_requests,omitempty"`
	// How many workers are actively processing prompt generations in this horde in the past 5 minutes.
	WorkerCount int `json:"worker_count,omitempty"`
	// How many workers are actively processing prompt generations in this horde in the past 5 minutes.
	TextWorkerCount int `json:"text_worker_count,omitempty"`
	// How many worker threads are actively processing prompt generations in this horde in the past 5 minutes.
	ThreadCount int `json:"thread_count,omitempty"`
	// How many worker threads are actively processing prompt generations in this horde in the past 5 minutes.
	TextThreadCount int `json:"text_thread_count,omitempty"`
	// The amount of megapixelsteps in waiting and processing requests currently in this horde.
	QueuedMegapixelsteps float64 `json:"queued_megapixelsteps,omitempty"`
	// How many megapixelsteps this horde generated in the last minute.
	PastMinuteMegapixelsteps float64 `json:"past_minute_megapixelsteps,omitempty"`
	// The amount of image interrogations waiting and processing currently in this horde.
	QueuedForms int `json:"queued_forms,omitempty"`
	// How many workers are actively processing image interrogations in this horde in the past 5 minutes.
	InterrogatorCount int `json:"interrogator_count,omitempty"`
	// How many worker threads are actively processing image interrogation in this horde in the past 5 minutes.
	InterrogatorThreadCount int `json:"interrogator_thread_count,omitempty"`
	// The amount of tokens in waiting and processing requests currently in this horde.
	QueuedTokens float64 `json:"queued_tokens,omitempty"`
	// How many tokens this horde generated in the last minute.
	PastMinuteTokens float64 `json:"past_minute_tokens,omitempty"`
}

// Newspiece represents a single news item from the horde.
type Newspiece struct {
	// The date this newspiece was published.
	DatePublished string `json:"date_published,omitempty"`
	// The actual piece of news.
	Newspiece string `json:"newspiece,omitempty"`
	// How critical this piece of news is.
	Importance string `json:"importance,omitempty"`
	// Tags for this newspiece.
	Tags []string `json:"tags,omitempty"`
	// The title of this newspiece.
	Title string `json:"title,omitempty"`
	// URLs for more information about this newspiece.
	MoreInfoURLs []string `json:"more_info_urls,omitempty"`
}

// WorkerDetailsLite provides basic information about a worker.
type WorkerDetailsLite struct {
	// The Type of worker this is.
	Type ModelType `json:"type,omitempty"` // image, text, interrogation
	// The Name given to this worker.
	Name string `json:"name,omitempty"`
	// The UUID of this worker.
	ID string `json:"id,omitempty"`
	// True if the worker has checked-in the past 5 minutes.
	Online bool `json:"online,omitempty"`
}

// WorkerKudosDetails provides a breakdown of kudos earned by a worker.
type WorkerKudosDetails struct {
	// How much Kudos this worker has received for generating images.
	Generated float64 `json:"generated,omitempty"`
	// How much Kudos this worker has received for staying online longer.
	Uptime int `json:"uptime,omitempty"`
}

// TeamDetailsLite provides basic information about a team.
type TeamDetailsLite struct {
	// The Name given to this team.
	Name string `json:"name,omitempty"`
	// The UUID of this team.
	ID string `json:"id,omitempty"`
}

// WorkerDetails provides comprehensive information about a worker.
type WorkerDetails struct {
	WorkerDetailsLite
	// How many images this worker has generated.
	RequestsFulfilled int `json:"requests_fulfilled,omitempty"`
	// How many Kudos this worker has been rewarded in total.
	KudosRewards float64 `json:"kudos_rewards,omitempty"`
	// Breakdown of kudos earned.
	KudosDetails *WorkerKudosDetails `json:"kudos_details,omitempty"`
	// The average performance of this worker in human readable form.
	Performance string `json:"performance,omitempty"`
	// How many threads this worker is running.
	Threads int `json:"threads,omitempty"`
	// The amount of seconds this worker has been online for this AI Horde.
	Uptime int `json:"uptime,omitempty"`
	// When True, this worker will not pick up any new requests.
	MaintenanceMode bool `json:"maintenance_mode,omitempty"`
	// (Privileged) When True, this worker not be given any new requests.
	Paused bool `json:"paused,omitempty"`
	// Extra information or comments about this worker provided by its owner.
	Info string `json:"info,omitempty"`
	// Whether this worker can generate NSFW requests or not.
	NSFW bool `json:"nsfw,omitempty"`
	// Privileged or public if the owner has allowed it. The alias of the owner of this worker.
	Owner string `json:"owner,omitempty"`
	// Privileged. The last known IP this worker has connected from.
	IPAddr string `json:"ipaddr,omitempty"`
	// The worker is trusted to return valid generations.
	Trusted bool `json:"trusted,omitempty"`
	// The worker's owner has been flagged for suspicious activity. This worker will not be given any jobs to process.
	Flagged bool `json:"flagged,omitempty"`
	// (Privileged) How much suspicion this worker has accumulated.
	Suspicious int `json:"suspicious,omitempty"`
	// How many jobs this worker has left uncompleted after it started them.
	UncompletedJobs int `json:"uncompleted_jobs,omitempty"`
	// Which models this worker if offering.
	Models []string `json:"models,omitempty"`
	// Which forms this worker if offering (e.g., interrogation types).
	Forms []string `json:"forms,omitempty"`
	// Team details if the worker belongs to a team.
	Team *TeamDetailsLite `json:"team,omitempty"`
	// (Privileged) Contact details for the horde admins to reach the owner of this worker in emergencies.
	Contact string `json:"contact,omitempty"` // MinLen: 5, MaxLen: 500
	// The bridge agent name, version and website.
	BridgeAgent string `json:"bridge_agent"` // Default: unknown:0:unknown, MaxLen: 1000
	// The maximum pixels in resolution this worker can generate.
	MaxPixels int `json:"max_pixels,omitempty"`
	// How many megapixelsteps this worker has generated until now.
	MegapixelstepsGenerated float64 `json:"megapixelsteps_generated,omitempty"`
	// If True, this worker supports and allows img2img requests.
	Img2Img bool `json:"img2img,omitempty"`
	// If True, this worker supports and allows inpainting requests.
	Painting bool `json:"painting,omitempty"`
	// If True, this worker supports and allows post-processing requests.
	PostProcessing bool `json:"post-processing,omitempty"` // Note hyphen
	// If True, this worker supports and allows lora requests.
	Lora bool `json:"lora,omitempty"`
	// If True, this worker supports and allows controlnet requests.
	ControlNet bool `json:"controlnet,omitempty"`
	// If True, this worker supports and allows SDXL controlnet requests.
	SDXLControlNet bool `json:"sdxl_controlnet,omitempty"`
	// The maximum tokens this worker can generate.
	MaxLength int `json:"max_length,omitempty"`
	// The maximum tokens this worker can read.
	MaxContextLength int `json:"max_context_length,omitempty"`
	// How many tokens this worker has generated until now.
	TokensGenerated float64 `json:"tokens_generated,omitempty"`
	// Active messages for this worker.
	Messages []ResponseModelMessage `json:"messages,omitempty"`
}

// ModifyWorkerInput defines fields for modifying a worker.
type ModifyWorkerInput struct {
	// Set to true to put this worker into maintenance.
	Maintenance *bool `json:"maintenance,omitempty"`
	// if maintenance is True, you can optionally provide a message to be used instead of the default maintenance message.
	MaintenanceMsg string `json:"maintenance_msg,omitempty"`
	// (Mods only) Set to true to pause this worker.
	Paused *bool `json:"paused,omitempty"`
	// You can optionally provide a server note which will be seen in the server details. No profanity allowed!
	Info *string `json:"info,omitempty"` // MaxLen: 1000
	// When this is set, it will change the worker's name. No profanity allowed!
	Name *string `json:"name,omitempty"` // MinLen: 5, MaxLen: 100
	// The team towards which this worker contributes kudos. It an empty string ('') is passed, it will leave the worker without a team.
	Team *string `json:"team,omitempty"` // MaxLen: 36 (Team ID)
}

// ModifyWorker represents the response after modifying a worker.
type ModifyWorker struct {
	// The new state of the 'maintenance' var for this worker.
	Maintenance bool `json:"maintenance,omitempty"`
	// The new state of the 'paused' var for this worker.
	Paused bool `json:"paused,omitempty"`
	// The new state of the 'info' var for this worker.
	Info string `json:"info,omitempty"`
	// The new name for this this worker.
	Name string `json:"name,omitempty"`
	// The new team ID of this worker.
	Team string `json:"team,omitempty"`
}

// DeletedWorker represents the response after deleting a worker.
type DeletedWorker struct {
	// The ID of the deleted worker.
	DeletedID string `json:"deleted_id,omitempty"`
	// The Name of the deleted worker.
	DeletedName string `json:"deleted_name,omitempty"`
}

// CreateTeamInput defines fields for creating a new team.
type CreateTeamInput struct {
	// The name of the team. No profanity allowed!
	Name string `json:"name"` // MinLen: 3, MaxLen: 100
	// Extra information or comments about this team.
	Info string `json:"info,omitempty"` // MinLen: 3, MaxLen: 1000
}

// TeamDetails provides comprehensive information about a team.
type TeamDetails struct {
	TeamDetailsLite
	// Extra information or comments about this team provided by its owner.
	Info string `json:"info,omitempty"`
	// How many images this team's workers have generated.
	RequestsFulfilled int `json:"requests_fulfilled,omitempty"`
	// How many Kudos the workers in this team have been rewarded while part of this team.
	Kudos float64 `json:"kudos,omitempty"`
	// The total amount of time workers have stayed online while on this team.
	Uptime int `json:"uptime,omitempty"`
	// The alias of the user which created this team.
	Creator string `json:"creator,omitempty"`
	// How many workers have been dedicated to this team.
	WorkerCount int `json:"worker_count,omitempty"`
	// List of workers in the team.
	Workers []WorkerDetailsLite `json:"workers,omitempty"`
	// List of models run by workers in the team.
	Models []ActiveModelLite `json:"models,omitempty"`
}

// ModifyTeam represents the response after creating or modifying a team.
type ModifyTeam struct {
	// The ID of the team.
	ID string `json:"id,omitempty"`
	// The Name of the team.
	Name string `json:"name,omitempty"`
	// The Info of the team.
	Info string `json:"info,omitempty"`
}

// ModifyTeamInput defines fields for updating a team's information.
type ModifyTeamInput struct {
	// The name of the team. No profanity allowed!
	Name *string `json:"name,omitempty"` // MinLen: 3, MaxLen: 100
	// Extra information or comments about this team.
	Info *string `json:"info,omitempty"` // MinLen: 3, MaxLen: 1000
}

// DeletedTeam represents the response after deleting a team.
type DeletedTeam struct {
	// The ID of the deleted team.
	DeletedID string `json:"deleted_id,omitempty"`
	// The Name of the deleted team.
	DeletedName string `json:"deleted_name,omitempty"`
}

// SharedKeyInput defines fields for creating or modifying a shared key.
type SharedKeyInput struct {
	// The Kudos limit assigned to this key. If -1, then anyone with this key can use an unlimited amount of kudos from this account.
	Kudos *int `json:"kudos,omitempty"` // Default: 5000, Min: -1, Max: 50000000
	// The amount of days after which this key will expire. If -1, this key will not expire.
	Expiry *int `json:"expiry,omitempty"` // Default: -1, Min: -1
	// A descriptive name for this key.
	Name *string `json:"name,omitempty"` // MinLen: 3, MaxLen: 255
	// The maximum amount of image pixels this key can generate per job. -1 means unlimited.
	MaxImagePixels *int `json:"max_image_pixels,omitempty"` // Default: -1, Min: -1, Max: 4194304
	// The maximum amount of image steps this key can use per job. -1 means unlimited.
	MaxImageSteps *int `json:"max_image_steps,omitempty"` // Default: -1, Min: -1, Max: 500
	// The maximum amount of text tokens this key can generate per job. -1 means unlimited.
	MaxTextTokens *int `json:"max_text_tokens,omitempty"` // Default: -1, Min: -1, Max: 500
}

// SharedKeyDetails provides information about a shared key.
type SharedKeyDetails struct {
	// The SharedKey ID.
	ID string `json:"id,omitempty"`
	// The owning user's unique Username.
	Username string `json:"username,omitempty"`
	// The Shared Key Name.
	Name string `json:"name,omitempty"`
	// The Kudos limit assigned to this key.
	Kudos int `json:"kudos,omitempty"`
	// The date at which this API key will expire. (date-time)
	Expiry string `json:"expiry,omitempty"`
	// How much kudos has been utilized via this shared key until now.
	Utilized int `json:"utilized,omitempty"`
	// The maximum amount of image pixels this key can generate per job. -1 means unlimited.
	MaxImagePixels int `json:"max_image_pixels,omitempty"`
	// The maximum amount of image steps this key can use per job. -1 means unlimited.
	MaxImageSteps int `json:"max_image_steps,omitempty"`
	// The maximum amount of text tokens this key can generate per job. -1 means unlimited.
	MaxTextTokens int `json:"max_text_tokens,omitempty"`
}

// ModelInterrogationInputStable defines the input for an image interrogation request.
type ModelInterrogationInputStable struct {
	// The forms of interrogation to perform.
	Forms []ModelInterrogationFormStable `json:"forms,omitempty"`
	// The public URL of the image to interrogate.
	SourceImage string `json:"source_image,omitempty"`
	// When True, allows slower workers to pick up this request. Disabling this incurs an extra kudos cost.
	SlowWorkers *bool `json:"slow_workers,omitempty"` // Default: true
	// Provide a URL where the AI Horde will send a POST call after each delivered generation.
	Webhook string `json:"webhook,omitempty"` // MinLen: 10, MaxLen: 1024
}

// ModelInterrogationFormStable defines a specific interrogation task.
type ModelInterrogationFormStable struct {
	// The type of interrogation this is.
	Name ModelInterrogationFormType `json:"name"`
	// Payload for the interrogation form (currently seems unused in spec).
	Payload map[string]string `json:"payload,omitempty"` // Swagger: ModelInterrogationFormPayloadStable (object with string additionalProperties)
}

// RequestInterrogationResponse represents the response after queueing an interrogation request.
type RequestInterrogationResponse struct {
	// The UUID of the request. Use this to retrieve the request status in the future.
	ID string `json:"id,omitempty"`
	// Any extra information from the horde about this request.
	Message string `json:"message,omitempty"`
}

// InterrogationStatus represents the status of an interrogation request.
type InterrogationStatus struct {
	// The overall status of this interrogation (e.g., "processing", "done", "error").
	State string `json:"state,omitempty"`
	// Status of individual interrogation forms.
	Forms []InterrogationFormStatus `json:"forms,omitempty"`
}

// InterrogationFormStatus represents the status of a single interrogation form.
type InterrogationFormStatus struct {
	// The name of this interrogation form.
	Form ModelInterrogationFormType `json:"form,omitempty"`
	// The status of this specific form (e.g., "waiting", "processing", "done", "error").
	State string `json:"state,omitempty"`
	// The result of the interrogation for this form. Structure depends on the form type.
	Result map[string]interface{} `json:"result,omitempty"` // Swagger: InterrogationFormResult (object with object additionalProperties)
}

// InterrogationPopInput defines fields for popping interrogation requests.
type InterrogationPopInput struct {
	// The Name of the Worker.
	Name string `json:"name,omitempty"`
	// Users with priority to use this worker.
	PriorityUsernames []string `json:"priority_usernames,omitempty"`
	// The type of interrogation this worker can fulfil.
	Forms []ModelInterrogationFormType `json:"forms,omitempty"`
	// The amount of forms to pop at the same time.
	Amount *int `json:"amount,omitempty"` // Default: 1
	// The worker name, version and website.
	BridgeAgent string `json:"bridge_agent,omitempty"` // Default: unknown, MaxLen: 1000
	// How many threads this worker is running.
	Threads *int `json:"threads,omitempty"` // Default: 1, Min: 1, Max: 100
	// The maximum amount of 512x512 tiles this worker can post-process.
	MaxTiles *int `json:"max_tiles,omitempty"` // Default: 16, Min: 1, Max: 256
}

// InterrogationPopPayload represents the data received when popping interrogation requests.
type InterrogationPopPayload struct {
	// The popped interrogation forms.
	Forms []InterrogationPopFormPayload `json:"forms,omitempty"`
	// Details about skipped requests.
	Skipped *NoValidInterrogationsFound `json:"skipped,omitempty"`
}

// InterrogationPopFormPayload represents a single popped interrogation form.
type InterrogationPopFormPayload struct {
	// The UUID of the interrogation form. Use this to post the results in the future.
	ID string `json:"id,omitempty"`
	// The name of this interrogation form.
	Form ModelInterrogationFormType `json:"form,omitempty"`
	// Payload for the interrogation form (currently seems unused in spec).
	Payload map[string]string `json:"payload,omitempty"` // Swagger: ModelInterrogationFormPayloadStable
	// The URL From which the source image can be downloaded.
	SourceImage string `json:"source_image,omitempty"`
	// The URL in which the post-processed image can be uploaded (for post-processing forms).
	R2Upload string `json:"r2_upload,omitempty"`
}

// NoValidInterrogationsFound provides reasons why an interrogation worker skipped requests.
type NoValidInterrogationsFound struct {
	// How many waiting requests were skipped because they demanded a specific worker.
	WorkerID int `json:"worker_id,omitempty"`
	// How many waiting requests were skipped because they demanded a trusted worker which this worker is not.
	Untrusted int `json:"untrusted,omitempty"`
	// How many waiting requests were skipped because they require a higher version of the bridge than this worker is running.
	BridgeVersion int `json:"bridge_version,omitempty"`
}

// InterrogationSubmitInput defines the input for submitting interrogation results.
type InterrogationSubmitInput struct {
	// The ID of the interrogation form being submitted.
	ID string `json:"id,omitempty"`
	// The result of the interrogation (structure depends on the form type).
	Result map[string]interface{} `json:"result,omitempty"` // Swagger defines as string, but likely should be object matching InterrogationFormResult
	// The state of the submission ("done", "error").
	State string `json:"state,omitempty"` // Should likely be enum, e.g., "done", "error"
}

// PutNewFilter defines fields for creating a new regex filter (Moderator only).
type PutNewFilter struct {
	// The regex for this filter.
	Regex string `json:"regex"`
	// The integer defining this filter type.
	FilterType int `json:"filter_type"` // Min: 10, Max: 29
	// Description about this regex.
	Description string `json:"description,omitempty"`
	// The replacement string for this regex.
	Replacement string `json:"replacement,omitempty"` // Default: ""
}

// FilterDetails provides information about a specific regex filter.
type FilterDetails struct {
	// The UUID of this filter.
	ID string `json:"id"`
	// The regex for this filter.
	Regex string `json:"regex"`
	// The integer defining this filter type.
	FilterType int `json:"filter_type"` // Min: 10, Max: 29
	// Description about this regex.
	Description string `json:"description,omitempty"`
	// The replacement string for this regex.
	Replacement string `json:"replacement,omitempty"` // Default: ""
	// The moderator which added or last updated this regex.
	User string `json:"user"`
}

// FilterPromptSuspicion represents the response when checking prompt suspicion (Moderator only).
type FilterPromptSuspicion struct {
	// Rates how suspicious the provided prompt is. A suspicion over 2 means it would be blocked.
	Suspicion string `json:"suspicion"` // Note: Swagger says string, likely float or int? Default: 0
	// Which words in the prompt matched the filters.
	Matches []string `json:"matches,omitempty"`
}

// FilterRegex represents the combined regex for a specific filter type.
type FilterRegex struct {
	// The integer defining this filter type.
	FilterType int `json:"filter_type"` // Min: 10, Max: 29
	// The full regex for this filter type.
	Regex string `json:"regex"`
}

// PatchExistingFilter defines fields for modifying an existing regex filter (Moderator only).
type PatchExistingFilter struct {
	// The regex for this filter.
	Regex *string `json:"regex,omitempty"`
	// The integer defining this filter type.
	FilterType *int `json:"filter_type,omitempty"` // Min: 10, Max: 29
	// Description about this regex.
	Description *string `json:"description,omitempty"`
	// The replacement string for this regex.
	Replacement *string `json:"replacement,omitempty"` // Default: ""
}

// AddTimeoutIPInput defines fields for adding an IP/CIDR to timeout (Moderator only).
type AddTimeoutIPInput struct {
	// The IP address or CIDR to add from timeout.
	IPAddr string `json:"ipaddr"` // MinLen: 7, MaxLen: 40
	// For how many hours to put this IP in timeout.
	Hours int `json:"hours"` // Min: 1, Max: 720
}

// DeleteTimeoutIPInput defines fields for removing an IP/CIDR from timeout (Moderator only).
type DeleteTimeoutIPInput struct {
	// The IP address or CIDR to remove from timeout.
	IPAddr string `json:"ipaddr"` // MinLen: 7, MaxLen: 40
}

// IPTimeout represents an IP/CIDR currently in timeout.
type IPTimeout struct {
	// The CIDR which is in timeout.
	IPAddr string `json:"ipaddr"` // MinLen: 7, MaxLen: 40
	// How many more seconds this IP block is in timeout
	Seconds int `json:"seconds"`
}

// AddWorkerTimeout defines fields for putting a worker's IP in timeout (Moderator only).
type AddWorkerTimeout struct {
	// For how many days to put this worker's IP in timeout.
	Days int `json:"days"` // Min: 1, Max: 30
}

// StatsImgTotals provides image generation statistics over different periods.
type StatsImgTotals struct {
	Minute *SinglePeriodImgStat `json:"minute,omitempty"`
	Hour   *SinglePeriodImgStat `json:"hour,omitempty"`
	Day    *SinglePeriodImgStat `json:"day,omitempty"`
	Month  *SinglePeriodImgStat `json:"month,omitempty"`
	Total  *SinglePeriodImgStat `json:"total,omitempty"`
}

// SinglePeriodImgStat provides image generation stats for a single period.
type SinglePeriodImgStat struct {
	// The amount of images generated during this period.
	Images int `json:"images,omitempty"`
	// The amount of pixelsteps generated during this period.
	PS int `json:"ps,omitempty"`
}

// ImgModelStats provides image generation statistics per model over different periods.
type ImgModelStats struct {
	Day   map[string]int `json:"day,omitempty"`   // ModelName: Count
	Month map[string]int `json:"month,omitempty"` // ModelName: Count
	Total map[string]int `json:"total,omitempty"` // ModelName: Count
}

// StatsTxtTotals provides text generation statistics over different periods.
type StatsTxtTotals struct {
	Minute *SinglePeriodTxtStat `json:"minute,omitempty"`
	Hour   *SinglePeriodTxtStat `json:"hour,omitempty"`
	Day    *SinglePeriodTxtStat `json:"day,omitempty"`
	Month  *SinglePeriodTxtStat `json:"month,omitempty"`
	Total  *SinglePeriodTxtStat `json:"total,omitempty"`
}

// SinglePeriodTxtStat provides text generation stats for a single period.
type SinglePeriodTxtStat struct {
	// The amount of text requests generated during this period.
	Requests int `json:"requests,omitempty"`
	// The amount of tokens generated during this period.
	Tokens int `json:"tokens,omitempty"`
}

// TxtModelStats provides text generation statistics per model over different periods.
type TxtModelStats struct {
	Day   map[string]int `json:"day,omitempty"`   // ModelName: Count
	Month map[string]int `json:"month,omitempty"` // ModelName: Count
	Total map[string]int `json:"total,omitempty"` // ModelName: Count
}

// HordeDocument represents a document available in HTML or Markdown format.
type HordeDocument struct {
	// The document in html format.
	HTML string `json:"html,omitempty"`
	// The document in markdown format.
	Markdown string `json:"markdown,omitempty"`
}

// ModelStyleInputStable defines the input for creating or modifying an image style.
type ModelStyleInputStable struct {
	// The name for the style. Case-sensitive and unique per user.
	Name string `json:"name"` // MinLen: 1, MaxLen: 100
	// Some information about this style.
	Info *string `json:"info,omitempty"` // MinLen: 10, MaxLen: 1000
	// The prompt template. Must include '{p}' for prompt and '{np}' for negative prompt.
	Prompt *string `json:"prompt,omitempty"` // Default: "{p}{np}", MinLen: 7
	// Style parameters.
	Params *ModelStyleInputParamsStable `json:"params,omitempty"`
	// When true this style will be listed among all styles publicly.
	Public *bool `json:"public,omitempty"` // Default: true
	// When true, it signified this style is expected to generare NSFW images primarily.
	NSFW *bool `json:"nsfw,omitempty"` // Default: false
	// Tags describing this style. Used for filtering and discovery.
	Tags []string `json:"tags,omitempty"` // Item MinLen: 1, MaxLen: 25
	// The models to use with this style.
	Models []string `json:"models,omitempty"` // Item MinLen: 1
	// The UUID of a shared key which will be used to fulfil this style when active.
	SharedKey string `json:"sharedkey,omitempty"` // MinLen: 36, MaxLen: 36
}

// ModelStyleInputParamsStable defines the style parameters for image generation.
type ModelStyleInputParamsStable struct {
	ModelStyleInputParamsStableNoDefaults
	// The number of steps to use for generation.
	Steps *int `json:"steps,omitempty"` // Min: 1, Max: 500
}

// ModelStyleInputParamsStableNoDefaults contains style parameters without default values.
type ModelStyleInputParamsStableNoDefaults struct {
	// The sampler to use for generation.
	SamplerName *ModelGenerationInputSampler `json:"sampler_name,omitempty"`
	// The Classifier-Free Guidance scale.
	CfgScale *float64 `json:"cfg_scale,omitempty"` // Min: 0, Max: 100
	// The denoising strength for img2img/remix.
	DenoisingStrength *float64 `json:"denoising_strength,omitempty"` // Min: 0.01, Max: 1.0
	// The denoising strength for hires fix.
	HiresFixDenoisingStrength *float64 `json:"hires_fix_denoising_strength,omitempty"` // Min: 0.01, Max: 1.0
	// The height of the image to generate.
	Height *int `json:"height,omitempty"` // Min: 64, Max: 3072, MultipleOf: 64
	// The width of the image to generate.
	Width *int `json:"width,omitempty"` // Min: 64, Max: 3072, MultipleOf: 64
	// The list of post-processors to apply to the image, in order.
	PostProcessing []ModelGenerationInputPostProcessingType `json:"post_processing,omitempty"`
	// Set to True to enable karras noise scheduling tweaks.
	Karras *bool `json:"karras,omitempty"`
	// Set to True to create images that stitch together seamlessly.
	Tiling *bool `json:"tiling,omitempty"`
	// Set to True to process the image at base resolution before upscaling and re-processing or to use Stable Cascade 2-pass.
	HiresFix *bool `json:"hires_fix,omitempty"`
	// The number of CLIP language processor layers to skip.
	ClipSkip *int `json:"clip_skip,omitempty"` // Min: 1, Max: 12
	// The strength of the face fixer post-processor.
	FacefixerStrength *float64 `json:"facefixer_strength,omitempty"` // Min: 0, Max: 1.0
	// LoRAs to apply during generation.
	Loras []ModelPayloadLorasStable `json:"loras,omitempty"`
	// Textual Inversions to apply during generation.
	Tis []ModelPayloadTextualInversionsStable `json:"tis,omitempty"`
	// Special payload for specific model needs.
	Special map[string]interface{} `json:"special,omitempty"`
	// Explicitly specify the horde-engine workflow to use.
	Workflow *ModelGenerationInputWorkflow `json:"workflow,omitempty"`
	// Set to True to generate the image using Layer Diffuse, creating an image with a transparent background.
	Transparent *bool `json:"transparent,omitempty"`
}

// StyleStable represents a detailed image style.
type StyleStable struct {
	ModelStyleInputStable
	// The UUID of the style.
	ID string `json:"id,omitempty"` // MinLen: 36, MaxLen: 36
	// The amount of times this style has been used in generations.
	UseCount int `json:"use_count,omitempty"`
	// The alias of the user to whom this style belongs to.
	Creator string `json:"creator,omitempty"`
	// Example images for this style.
	Examples []StyleExample `json:"examples,omitempty"`
	// Details of the shared key associated with this style, if any.
	SharedKey *SharedKeyDetails `json:"shared_key,omitempty"`
}

// StyleExample represents an example image for a style.
type StyleExample struct {
	InputStyleExamplePost
	// The UUID of this example.
	ID string `json:"id,omitempty"`
}

// InputStyleExamplePost defines fields for creating or modifying a style example.
type InputStyleExamplePost struct {
	// URL of the example image.
	URL string `json:"url,omitempty"`
	// When true this image is to be used as the primary example for this style.
	Primary *bool `json:"primary,omitempty"`
}

// StyleModify represents the response after creating or modifying a style or collection.
type StyleModify struct {
	// The UUID of the style or collection.
	ID string `json:"id,omitempty"`
	// Any extra information from the horde about this request.
	Message string `json:"message,omitempty"`
	// Warnings associated with the request.
	Warnings []RequestSingleWarning `json:"warnings,omitempty"`
}

// ModelStylePatchStable defines fields for patching an image style.
type ModelStylePatchStable struct {
	// The name for the style. Case-sensitive and unique per user.
	Name *string `json:"name,omitempty"` // MinLen: 1, MaxLen: 100
	// Extra information about this style.
	Info *string `json:"info,omitempty"` // MinLen: 1, MaxLen: 1000
	// The prompt template. Must include '{p}' and '{np}'.
	Prompt *string `json:"prompt,omitempty"` // MinLen: 7
	// Style parameters.
	Params *ModelStyleInputParamsStable `json:"params,omitempty"`
	// When true this style will be listed among all styles publicly.
	Public *bool `json:"public,omitempty"` // Default: true
	// When true, it signified this style is expected to generare NSFW images primarily.
	NSFW *bool `json:"nsfw,omitempty"` // Default: false
	// Tags describing this style.
	Tags []string `json:"tags,omitempty"` // Item MinLen: 1, MaxLen: 25
	// The models to use with this style.
	Models []string `json:"models,omitempty"` // Item MinLen: 1
	// The UUID of a shared key which will be used to fulfil this style when active.
	SharedKey *string `json:"sharedkey,omitempty"` // MinLen: 36, MaxLen: 36
}

// ModelStyleInputKobold defines the input for creating or modifying a text style.
type ModelStyleInputKobold struct {
	// The name for the style. Case-sensitive and unique per user.
	Name string `json:"name"` // MinLen: 1, MaxLen: 100
	// Some information about this style.
	Info *string `json:"info,omitempty"` // MinLen: 10, MaxLen: 1000
	// The prompt template. Must include '{p}'.
	Prompt *string `json:"prompt,omitempty"` // Default: "{p}", MinLen: 3
	// Style parameters.
	Params *ModelStyleInputParamsKobold `json:"params,omitempty"`
	// When true this style will be listed among all styles publicly.
	Public *bool `json:"public,omitempty"` // Default: true
	// When true, it signified this style is expected to generare NSFW images primarily.
	NSFW *bool `json:"nsfw,omitempty"` // Default: false
	// Tags describing this style.
	Tags []string `json:"tags,omitempty"` // Item MinLen: 1, MaxLen: 25
	// The models to use with this style.
	Models []string `json:"models,omitempty"` // Item MinLen: 1
}

// ModelStyleInputParamsKobold defines the style parameters for text generation.
type ModelStyleInputParamsKobold struct {
	ModelPayloadStyleKobold
	// Add specific fields if any (Swagger shows empty)
}

// StyleKobold represents a detailed text style.
type StyleKobold struct {
	ModelStyleInputKobold
	// The UUID of the style.
	ID string `json:"id,omitempty"`
	// The amount of times this style has been used in generations.
	UseCount int `json:"use_count,omitempty"`
	// The alias of the user to whom this style belongs to.
	Creator string `json:"creator,omitempty"`
}

// ModelStylePatchKobold defines fields for patching a text style.
type ModelStylePatchKobold struct {
	// The name for the style.
	Name *string `json:"name,omitempty"` // MinLen: 1, MaxLen: 100
	// Extra information about this style.
	Info *string `json:"info,omitempty"` // MinLen: 1, MaxLen: 1000
	// The prompt template. Must include '{p}'.
	Prompt *string `json:"prompt,omitempty"` // MinLen: 7 (Note: Swagger says 7, likely typo, should be 3?)
	// Style parameters.
	Params *ModelStyleInputParamsKobold `json:"params,omitempty"`
	// When true this style will be listed among all styles publicly.
	Public *bool `json:"public,omitempty"` // Default: true
	// When true, it signified this style is expected to generare NSFW images primarily.
	NSFW *bool `json:"nsfw,omitempty"` // Default: false
	// Tags describing this style.
	Tags []string `json:"tags,omitempty"` // Item MinLen: 1, MaxLen: 25
	// The models to use with this style.
	Models []string `json:"models,omitempty"` // Item MinLen: 1
}

// InputModelCollection defines fields for creating or modifying a style collection.
type InputModelCollection struct {
	// The name for the collection. Case-sensitive and unique per user.
	Name *string `json:"name,omitempty"` // MinLen: 1, MaxLen: 100
	// Extra information about this collection.
	Info *string `json:"info,omitempty"` // MinLen: 1, MaxLen: 1000
	// When true this collection will be listed among all collections publicly.
	Public *bool `json:"public,omitempty"` // Default: true
	// The styles (IDs or names) to include in this collection.
	Styles []string `json:"styles,omitempty"` // Item MinLen: 1
}

// ResponseModelCollection represents a style collection.
type ResponseModelCollection struct {
	// The UUID of the collection.
	ID string `json:"id,omitempty"`
	// The name for the collection.
	Name string `json:"name,omitempty"` // MinLen: 1, MaxLen: 100
	// The kind of styles stored in this collection.
	Type ModelType `json:"type,omitempty"` // image or text
	// Extra information about this collection.
	Info string `json:"info,omitempty"` // MinLen: 1, MaxLen: 1000
	// When true this collection will be listed among all collection publicly.
	Public bool `json:"public,omitempty"` // Default: true
	// The styles included in this collection.
	Styles []ResponseModelStylesShort `json:"styles,omitempty"`
	// The amount of times this collection has been used in generations.
	UseCount int `json:"use_count,omitempty"`
}

// ResponseModelStylesShort provides minimal style information (name and ID).
type ResponseModelStylesShort struct {
	// The unique name for this style (e.g., user#id::style::stylename)
	Name string `json:"name,omitempty"`
	// The ID of this style
	ID string `json:"id,omitempty"`
}

// ResponseModelMessage represents a message intended for a worker.
type ResponseModelMessage struct {
	// The ID of the worker this message is intended for.
	WorkerID string `json:"worker_id,omitempty"` // MinLen: 36, MaxLen: 36
	// The message sent
	Message string `json:"message"` // MinLen: 1, MaxLen: 10240
	// The origin of this message. Typically this will be the horde moderators.
	Origin string `json:"origin,omitempty"` // MinLen: 1, MaxLen: 255
	// The number of hours after which this message expires.
	Expiry *int `json:"expiry,omitempty"` // Default: 12, Min: 1, Max: 720
	// The ID of the message (present in response, not input for POST)
	ID string `json:"id,omitempty"`
}

// KudosAwardInput defines fields for awarding kudos (privileged).
type KudosAwardInput struct {
	Username string `json:"username,omitempty"`
	Amount   int    `json:"amount,omitempty"`
}

// KudosTransferInput defines fields for transferring kudos.
type KudosTransferInput struct {
	Username string `json:"username,omitempty"`
	Amount   int    `json:"amount,omitempty"`
}

// FilterCheckInput defines fields for checking prompt suspicion (Moderator only).
type FilterCheckInput struct {
	Prompt     string `json:"prompt,omitempty"`
	FilterType *int   `json:"filter_type,omitempty"`
}

// HordeModeInput defines fields for changing horde modes (Admin only).
type HordeModeInput struct {
	MaintenanceMode *bool `json:"maintenance_mode,omitempty"`
	InviteOnlyMode  *bool `json:"invite_only_mode,omitempty"`
	RaidMode        *bool `json:"raid_mode,omitempty"`
}
