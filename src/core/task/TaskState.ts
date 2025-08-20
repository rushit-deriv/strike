import { Anthropic } from "@anthropic-ai/sdk"
import { AssistantMessageContent } from "@core/assistant-message"
import { ClineAskResponse } from "@shared/WebviewMessage"

export class TaskState {
	// Streaming flags
	isStreaming = false
	isWaitingForFirstChunk = false
	didCompleteReadingStream = false

	// Content processing
	currentStreamingContentIndex = 0
	assistantMessageContent: AssistantMessageContent[] = []
	userMessageContent: (Anthropic.TextBlockParam | Anthropic.ImageBlockParam)[] = []
	userMessageContentReady = false

	// Presentation locks
	presentAssistantMessageLocked = false
	presentAssistantMessageHasPendingUpdates = false

	// Ask/Response handling
	askResponse?: ClineAskResponse
	askResponseText?: string
	askResponseImages?: string[]
	askResponseFiles?: string[]
	lastMessageTs?: number

	// Plan mode specific state
	isAwaitingPlanResponse = false
	didRespondToPlanAskBySwitchingMode = false

	// Context and history
	conversationHistoryDeletedRange?: [number, number]

	// Tool execution flags
	didRejectTool = false
	didAlreadyUseTool = false
	didEditFile: boolean = false

	// Consecutive request tracking
	consecutiveAutoApprovedRequestsCount: number = 0

	// Error tracking
	consecutiveMistakeCount: number = 0
	didAutomaticallyRetryFailedApiRequest = false
	checkpointTrackerErrorMessage?: string

	// Task Initialization
	isInitialized = false

	// Focus Chain / Todo List Management
	apiRequestCount: number = 0
	apiRequestsSinceLastTodoUpdate: number = 0
	currentFocusChainChecklist: string | null = null
	todoListWasUpdatedByUser: boolean = false

	// Task Abort / Cancellation
	abort: boolean = false
	didFinishAbortingStream = false
	abandoned = false

	// Auto-context summarization
	currentlySummarizing: boolean = false
	lastAutoCompactTriggerIndex?: number

	// Pentest Orchestration State
	/**
	 * Indicates whether the initial reconnaissance phase has been completed
	 * and a post-recon routing decision can be made.
	 */
	reconCompleted: boolean = false

	/**
	 * Current attack mode selected by the agent after recon.
	 * Examples: "baseline", "xss", "sqli", "idor", "ssrf", "lfi_rfi",
	 * "command_injection", "auth_bypass", "upload_bypass", "deserialization",
	 * "jwt", "waf_bypass", "csp_bypass".
	 */
	attackMode?: string

	/**
	 * Signals detected protective controls observed during recon or attacks
	 * that should influence subsequent payload crafting.
	 */
	detectedProtections: {
		wafVendorOrSignal?: string
		cspPolicySnippet?: string
		rateLimitingObserved?: boolean
	} = {}
}
