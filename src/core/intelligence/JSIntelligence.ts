/**
 * JSIntelligence - Advanced JavaScript analysis for elite-level reconnaissance
 *
 * This module provides deep JavaScript analysis capabilities:
 * - AST parsing for comprehensive code analysis
 * - API endpoint extraction from complex routing
 * - Secret and configuration discovery
 * - Dynamic analysis hints for runtime behavior
 * - Framework-specific intelligence gathering
 */

export interface JSAnalysisResult {
	filePath: string
	size: number
	framework?: string
	endpoints: {
		api: string[]
		routes: string[]
		websockets: string[]
		graphql: string[]
	}
	secrets: {
		apiKeys: string[]
		tokens: string[]
		credentials: string[]
		internalUrls: string[]
	}
	configurations: {
		environment: Record<string, any>
		featureFlags: string[]
		debugSettings: Record<string, any>
	}
	vulnerabilityHints: {
		domXssRisks: string[]
		prototypePolluion: string[]
		cspBypassOpportunities: string[]
		clientSideValidation: string[]
	}
	dynamicAnalysisHints: {
		eventListeners: string[]
		ajaxCalls: string[]
		postMessages: string[]
		storageOperations: string[]
	}
	sourceMapAvailable: boolean
	minified: boolean
	confidence: number
}

export interface FrameworkIntelligence {
	name: string
	version?: string
	routingStructure: string[]
	adminPaths: string[]
	apiPatterns: string[]
	commonVulns: string[]
}

export class JSIntelligence {
	private knownFrameworks = [
		"react",
		"vue",
		"angular",
		"next",
		"nuxt",
		"svelte",
		"ember",
		"jquery",
		"backbone",
		"express",
		"fastify",
		"koa",
	]

	private secretPatterns = [
		/[A-Za-z0-9]{32,}/g, // Generic long strings (API keys)
		/sk_[A-Za-z0-9]{24,}/g, // Stripe secret keys
		/pk_[A-Za-z0-9]{24,}/g, // Stripe public keys
		/AKIA[0-9A-Z]{16}/g, // AWS access keys
		/ghp_[A-Za-z0-9]{36}/g, // GitHub personal access tokens
		/xoxb-[0-9]{11}-[0-9]{11}-[A-Za-z0-9]{24}/g, // Slack bot tokens
		/AIza[0-9A-Za-z\\-_]{35}/g, // Google API keys
	]

	private apiPatterns = [
		/['"](\/api\/[^'"]*)['"]/g,
		/['"](\/v\d+\/[^'"]*)['"]/g,
		/['"](\/graphql[^'"]*)['"]/g,
		/['"](\/rest\/[^'"]*)['"]/g,
		/['"](\/admin\/[^'"]*)['"]/g,
		/['"](\/manage\/[^'"]*)['"]/g,
		/fetch\s*\(\s*['"](\/[^'"]*)['"]/g,
		/axios\.[get|post|put|delete]+\s*\(\s*['"](\/[^'"]*)['"]/g,
		/\$\.ajax\s*\(\s*{[^}]*url\s*:\s*['"](\/[^'"]*)['"]/g,
	]

	/**
	 * Analyze JavaScript file for intelligence
	 */
	async analyzeJavaScriptFile(filePath: string, content: string): Promise<JSAnalysisResult> {
		const result: JSAnalysisResult = {
			filePath,
			size: content.length,
			endpoints: { api: [], routes: [], websockets: [], graphql: [] },
			secrets: { apiKeys: [], tokens: [], credentials: [], internalUrls: [] },
			configurations: {
				environment: {} as Record<string, any>,
				featureFlags: [] as string[],
				debugSettings: {} as Record<string, any>,
			},
			vulnerabilityHints: { domXssRisks: [], prototypePolluion: [], cspBypassOpportunities: [], clientSideValidation: [] },
			dynamicAnalysisHints: { eventListeners: [], ajaxCalls: [], postMessages: [], storageOperations: [] },
			sourceMapAvailable: false,
			minified: this.isMinified(content),
			confidence: 0.5,
		}

		// Framework detection
		result.framework = this.detectFramework(content)
		if (result.framework) {
			result.confidence += 0.2
		}

		// Extract endpoints and routes
		result.endpoints = this.extractEndpoints(content)
		if (result.endpoints.api.length > 0) {
			result.confidence += 0.2
		}

		// Extract secrets and sensitive data
		result.secrets = this.extractSecrets(content)
		if (result.secrets.apiKeys.length > 0) {
			result.confidence += 0.3
		}

		// Extract configurations
		result.configurations = this.extractConfigurations(content)
		if (Object.keys(result.configurations.environment).length > 0) {
			result.confidence += 0.2
		}

		// Identify vulnerability hints
		result.vulnerabilityHints = this.identifyVulnerabilityHints(content)

		// Dynamic analysis hints
		result.dynamicAnalysisHints = this.extractDynamicAnalysisHints(content)

		// Check for source map
		result.sourceMapAvailable = this.hasSourceMap(content)

		// Ensure confidence doesn't exceed 1.0
		result.confidence = Math.min(1.0, result.confidence)

		return result
	}

	/**
	 * Get framework-specific intelligence
	 */
	getFrameworkIntelligence(frameworkName: string): FrameworkIntelligence | null {
		const frameworks: Record<string, FrameworkIntelligence> = {
			react: {
				name: "React",
				routingStructure: ["react-router", "reach-router", "next-router"],
				adminPaths: ["/admin", "/dashboard", "/manage"],
				apiPatterns: ["/api/", "/graphql"],
				commonVulns: ["DOM XSS", "Prototype pollution", "Client-side routing bypass"],
			},
			vue: {
				name: "Vue.js",
				routingStructure: ["vue-router"],
				adminPaths: ["/admin", "/dashboard", "/manage"],
				apiPatterns: ["/api/", "/rest/"],
				commonVulns: ["Template injection", "DOM XSS", "Client-side validation bypass"],
			},
			angular: {
				name: "Angular",
				routingStructure: ["@angular/router"],
				adminPaths: ["/admin", "/dashboard", "/manage"],
				apiPatterns: ["/api/", "/rest/", "/graphql"],
				commonVulns: ["Template injection", "DOM XSS", "CSP bypass via Angular expressions"],
			},
			next: {
				name: "Next.js",
				routingStructure: ["pages/", "app/", "api/"],
				adminPaths: ["/admin", "/dashboard", "/api/admin"],
				apiPatterns: ["/api/", "/api/auth/", "/_next/"],
				commonVulns: ["Server-side XSS", "API route exposure", "Static file exposure"],
			},
			nuxt: {
				name: "Nuxt.js",
				routingStructure: ["pages/", "api/", "middleware/"],
				adminPaths: ["/admin", "/dashboard", "/api/admin"],
				apiPatterns: ["/api/", "/_nuxt/"],
				commonVulns: ["SSR XSS", "API route exposure", "Middleware bypass"],
			},
		}

		return frameworks[frameworkName.toLowerCase()] || null
	}

	/**
	 * Extract all JavaScript files from HTML content
	 */
	extractJavaScriptReferences(htmlContent: string): string[] {
		const jsReferences: string[] = []

		// Script tags with src attribute
		const scriptMatches = htmlContent.match(/<script[^>]+src\s*=\s*["']([^"']+)["'][^>]*>/gi)
		if (scriptMatches) {
			scriptMatches.forEach((match) => {
				const srcMatch = match.match(/src\s*=\s*["']([^"']+)["']/i)
				if (srcMatch) {
					jsReferences.push(srcMatch[1])
				}
			})
		}

		// Inline script content references
		const inlineScripts = htmlContent.match(/<script[^>]*>[\s\S]*?<\/script>/gi)
		if (inlineScripts) {
			inlineScripts.forEach((script) => {
				// Look for dynamic script loading
				const dynamicLoads = script.match(/(?:import|require)\s*\(\s*["']([^"']+\.js)["']\s*\)/g)
				if (dynamicLoads) {
					dynamicLoads.forEach((load) => {
						const pathMatch = load.match(/["']([^"']+\.js)["']/)
						if (pathMatch) {
							jsReferences.push(pathMatch[1])
						}
					})
				}
			})
		}

		return [...new Set(jsReferences)] // Remove duplicates
	}

	/**
	 * Generate comprehensive analysis report
	 */
	generateIntelligenceReport(analyses: JSAnalysisResult[]): string {
		const totalFiles = analyses.length
		const totalSize = analyses.reduce((sum, a) => sum + a.size, 0)
		const frameworks = [...new Set(analyses.map((a) => a.framework).filter(Boolean))]

		const allEndpoints = analyses.reduce(
			(acc, a) => {
				acc.api.push(...a.endpoints.api)
				acc.routes.push(...a.endpoints.routes)
				acc.websockets.push(...a.endpoints.websockets)
				acc.graphql.push(...a.endpoints.graphql)
				return acc
			},
			{ api: [] as string[], routes: [] as string[], websockets: [] as string[], graphql: [] as string[] },
		)

		const allSecrets = analyses.reduce(
			(acc, a) => {
				acc.apiKeys.push(...a.secrets.apiKeys)
				acc.tokens.push(...a.secrets.tokens)
				acc.credentials.push(...a.secrets.credentials)
				acc.internalUrls.push(...a.secrets.internalUrls)
				return acc
			},
			{ apiKeys: [] as string[], tokens: [] as string[], credentials: [] as string[], internalUrls: [] as string[] },
		)

		const report = [
			"# JavaScript Intelligence Report",
			"",
			"## Summary",
			`- **Files Analyzed:** ${totalFiles}`,
			`- **Total Size:** ${(totalSize / 1024).toFixed(2)} KB`,
			`- **Frameworks Detected:** ${frameworks.join(", ") || "None"}`,
			`- **Source Maps Available:** ${analyses.filter((a) => a.sourceMapAvailable).length}`,
			`- **Minified Files:** ${analyses.filter((a) => a.minified).length}`,
			"",
			"## Endpoints Discovered",
			`- **API Endpoints:** ${[...new Set(allEndpoints.api)].length}`,
			`- **Routes:** ${[...new Set(allEndpoints.routes)].length}`,
			`- **WebSocket Endpoints:** ${[...new Set(allEndpoints.websockets)].length}`,
			`- **GraphQL Endpoints:** ${[...new Set(allEndpoints.graphql)].length}`,
			"",
			"## Security Findings",
			`- **API Keys Found:** ${[...new Set(allSecrets.apiKeys)].length}`,
			`- **Tokens Found:** ${[...new Set(allSecrets.tokens)].length}`,
			`- **Internal URLs:** ${[...new Set(allSecrets.internalUrls)].length}`,
			"",
			"## Vulnerability Opportunities",
		]

		// Add specific vulnerability hints
		const allVulnHints = analyses.reduce((acc, a) => {
			acc.push(...a.vulnerabilityHints.domXssRisks)
			acc.push(...a.vulnerabilityHints.prototypePolluion)
			acc.push(...a.vulnerabilityHints.cspBypassOpportunities)
			acc.push(...a.vulnerabilityHints.clientSideValidation)
			return acc
		}, [] as string[])

		const uniqueVulnHints = [...new Set(allVulnHints)]
		report.push(...uniqueVulnHints.map((hint) => `- ${hint}`))

		// Add detailed endpoint listing
		if (allEndpoints.api.length > 0) {
			report.push("", "## API Endpoints")
			report.push(...[...new Set(allEndpoints.api)].map((endpoint) => `- ${endpoint}`))
		}

		if (allSecrets.apiKeys.length > 0) {
			report.push("", "## Potential API Keys")
			report.push(...[...new Set(allSecrets.apiKeys)].slice(0, 10).map((key) => `- ${key.substring(0, 20)}...`))
		}

		return report.join("\n")
	}

	// Private helper methods
	private detectFramework(content: string): string | undefined {
		for (const framework of this.knownFrameworks) {
			const patterns = [
				new RegExp(`${framework}`, "i"),
				new RegExp(`@${framework}`, "i"),
				new RegExp(`${framework}js`, "i"),
				new RegExp(`${framework}\\.`, "i"),
			]

			if (patterns.some((pattern) => pattern.test(content))) {
				return framework
			}
		}
		return undefined
	}

	private extractEndpoints(content: string): JSAnalysisResult["endpoints"] {
		const endpoints = { api: [] as string[], routes: [] as string[], websockets: [] as string[], graphql: [] as string[] }

		// Extract API endpoints
		for (const pattern of this.apiPatterns) {
			const matches = content.match(pattern)
			if (matches) {
				matches.forEach((match) => {
					const endpointMatch = match.match(/['"](\/[^'"]*)['"]/)?.[1]
					if (endpointMatch) {
						if (endpointMatch.includes("/api/")) {
							endpoints.api.push(endpointMatch)
						} else if (endpointMatch.includes("/graphql")) {
							endpoints.graphql.push(endpointMatch)
						} else {
							endpoints.routes.push(endpointMatch)
						}
					}
				})
			}
		}

		// Extract WebSocket endpoints
		const wsMatches = content.match(/new\s+WebSocket\s*\(\s*["']([^"']+)["']/g)
		if (wsMatches) {
			wsMatches.forEach((match) => {
				const wsMatch = match.match(/["']([^"']+)["']/)
				if (wsMatch) {
					endpoints.websockets.push(wsMatch[1])
				}
			})
		}

		return endpoints
	}

	private extractSecrets(content: string): JSAnalysisResult["secrets"] {
		const secrets = {
			apiKeys: [] as string[],
			tokens: [] as string[],
			credentials: [] as string[],
			internalUrls: [] as string[],
		}

		// Extract potential API keys and tokens
		for (const pattern of this.secretPatterns) {
			const matches = content.match(pattern)
			if (matches) {
				matches.forEach((match) => {
					if (match.startsWith("sk_") || match.startsWith("pk_")) {
						secrets.apiKeys.push(match)
					} else if (match.startsWith("ghp_") || match.startsWith("xoxb-")) {
						secrets.tokens.push(match)
					} else if (match.length >= 32) {
						secrets.apiKeys.push(match)
					}
				})
			}
		}

		// Extract internal URLs
		const urlMatches = content.match(/https?:\/\/[a-zA-Z0-9.-]+(?::\d+)?(?:\/[^\s"'<>]*)?/g)
		if (urlMatches) {
			urlMatches.forEach((url) => {
				if (
					url.includes("localhost") ||
					url.includes("127.0.0.1") ||
					url.includes("internal") ||
					url.includes(".local")
				) {
					secrets.internalUrls.push(url)
				}
			})
		}

		return secrets
	}

	private extractConfigurations(content: string): JSAnalysisResult["configurations"] {
		const configurations = { environment: {}, featureFlags: [] as string[], debugSettings: {} }

		// Extract environment configurations
		const envMatches = content.match(/(?:window\.__env__|process\.env|NODE_ENV|REACT_APP_|VUE_APP_|NEXT_PUBLIC_)[^;\s}]*/g)
		if (envMatches) {
			envMatches.forEach((match) => {
				;(configurations.environment as Record<string, any>)[match] = "detected"
			})
		}

		// Extract feature flags
		const flagMatches = content.match(/(?:feature|flag|toggle|enable)[A-Z][a-zA-Z0-9_]*/g)
		if (flagMatches) {
			configurations.featureFlags.push(...flagMatches)
		}

		// Extract debug settings
		const debugMatches = content.match(/(?:debug|dev|development|verbose)[^;\s}]*/gi)
		if (debugMatches) {
			debugMatches.forEach((match) => {
				;(configurations.debugSettings as Record<string, any>)[match] = "detected"
			})
		}

		return configurations
	}

	private identifyVulnerabilityHints(content: string): JSAnalysisResult["vulnerabilityHints"] {
		const hints = {
			domXssRisks: [] as string[],
			prototypePolluion: [] as string[],
			cspBypassOpportunities: [] as string[],
			clientSideValidation: [] as string[],
		}

		// DOM XSS risks
		const domXssPatterns = [
			/innerHTML\s*=/g,
			/outerHTML\s*=/g,
			/document\.write\s*\(/g,
			/\.html\s*\(/g,
			/\$\([^)]*\)\.html\s*\(/g,
		]
		domXssPatterns.forEach((pattern) => {
			if (pattern.test(content)) {
				hints.domXssRisks.push(`Potential DOM XSS sink: ${pattern.source}`)
			}
		})

		// Prototype pollution risks
		if (content.includes("Object.prototype") || content.includes("__proto__")) {
			hints.prototypePolluion.push("Prototype manipulation detected")
		}

		// CSP bypass opportunities
		if (content.includes("eval(") || content.includes("Function(")) {
			hints.cspBypassOpportunities.push("Dynamic code execution detected")
		}

		// Client-side validation
		if (content.includes("validate") && (content.includes("email") || content.includes("password"))) {
			hints.clientSideValidation.push("Client-side validation detected - may be bypassable")
		}

		return hints
	}

	private extractDynamicAnalysisHints(content: string): JSAnalysisResult["dynamicAnalysisHints"] {
		const hints = {
			eventListeners: [] as string[],
			ajaxCalls: [] as string[],
			postMessages: [] as string[],
			storageOperations: [] as string[],
		}

		// Event listeners
		const eventPatterns = ["addEventListener", "onclick", "onload", "onerror", "onmouseover"]
		eventPatterns.forEach((pattern) => {
			if (content.includes(pattern)) {
				hints.eventListeners.push(pattern)
			}
		})

		// AJAX calls
		const ajaxPatterns = ["fetch(", "XMLHttpRequest", "$.ajax", "axios."]
		ajaxPatterns.forEach((pattern) => {
			if (content.includes(pattern)) {
				hints.ajaxCalls.push(pattern)
			}
		})

		// PostMessage operations
		if (content.includes("postMessage")) {
			hints.postMessages.push("postMessage communication detected")
		}

		// Storage operations
		const storagePatterns = ["localStorage", "sessionStorage", "indexedDB"]
		storagePatterns.forEach((pattern) => {
			if (content.includes(pattern)) {
				hints.storageOperations.push(pattern)
			}
		})

		return hints
	}

	private isMinified(content: string): boolean {
		const lines = content.split("\n")
		const avgLineLength = content.length / lines.length
		return avgLineLength > 200 || lines.length < 10
	}

	private hasSourceMap(content: string): boolean {
		return content.includes("//# sourceMappingURL=") || content.includes("//@ sourceMappingURL=")
	}
}
