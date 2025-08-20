import { ToolDefinition } from "@core/prompts/model_prompts/jsonToolToXml"

export const setAttackModeToolDefinition: ToolDefinition = {
	name: "set_attack_mode",
	descriptionForAgent:
		"Selects the current attack mode after recon. Use this to route the agent into a dedicated prompt profile for a specific vulnerability class, e.g., XSS, SQLi, SSRF, IDOR, etc. This should be called once a clear hypothesis exists.",
	inputSchema: {
		type: "object",
		properties: {
			mode: {
				type: "string",
				description:
					"Attack mode identifier. One of: baseline, javascript_intel, xss, sqli, idor, ssrf, lfi_rfi, command_injection, auth_bypass, upload_bypass, deserialization, jwt, waf_bypass, csp_bypass.",
			},
			rationale: {
				type: "string",
				description:
					"Short reasoning and evidence that justify selecting this mode (observed endpoints, parameters, headers, stack, prior responses).",
			},
		},
		required: ["mode"],
	},
}
