import { ToolDefinition } from "@core/prompts/model_prompts/jsonToolToXml"

export const recordDetectionToolDefinition: ToolDefinition = {
	name: "record_detection",
	descriptionForAgent:
		"Records protective controls detected during recon/attacks to adapt payload strategy (e.g., WAF vendor hints, CSP policy snippets, rate limiting).",
	inputSchema: {
		type: "object",
		properties: {
			wafVendorOrSignal: {
				type: "string",
				description: "Optional WAF vendor name or signal (server headers, JS challenges, response body markers).",
			},
			cspPolicySnippet: {
				type: "string",
				description: "Optional CSP policy snippet extracted from response headers or meta tags.",
			},
			rateLimitingObserved: {
				type: "boolean",
				description: "Whether rate limiting or throttling was observed.",
			},
			notes: {
				type: "string",
				description: "Short notes/evidence about the detection.",
			},
		},
		required: [],
	},
}
