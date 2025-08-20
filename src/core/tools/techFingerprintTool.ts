import { ToolDefinition } from "@core/prompts/model_prompts/jsonToolToXml"

export const techFingerprintToolDefinition: ToolDefinition = {
	name: "tech_fingerprint",
	descriptionForAgent:
		"Retrieve HTTP response headers and a small HTML snippet to infer technologies (server, framework, CDN, WAF hints). Use this early in recon to guide hypotheses.",
	inputSchema: {
		type: "object",
		properties: {
			url: {
				type: "string",
				description: "Target URL to fingerprint (fully-qualified).",
			},
			maxBytes: {
				type: "number",
				description: "Optional max HTML bytes to capture from body for lightweight analysis (default 20480).",
			},
		},
		required: ["url"],
	},
}
