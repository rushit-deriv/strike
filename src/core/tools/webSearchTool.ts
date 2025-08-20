import { ToolDefinition } from "@core/prompts/model_prompts/jsonToolToXml"

export const webSearchToolDefinition: ToolDefinition = {
	name: "web_search",
	descriptionForAgent:
		"Perform a lightweight web search to discover sources (writeups, docs, research). Returns a small list of titles and links.",
	inputSchema: {
		type: "object",
		properties: {
			query: {
				type: "string",
				description: "Search query (e.g., 'auth bypass writeup').",
			},
			site: {
				type: "string",
				description: "Optional site limiter (e.g., 'portswigger.net' or 'hackerone.com').",
			},
			maxResults: {
				type: "number",
				description: "Max number of results to return (default 10).",
			},
		},
		required: ["query"],
	},
}
