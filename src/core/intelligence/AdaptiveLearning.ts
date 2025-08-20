/**
 * AdaptiveLearning - Machine learning-inspired system for improving attack success
 *
 * This system learns from:
 * - Failed attack attempts and their error patterns
 * - Successful exploits and their characteristics
 * - WAF/protection bypass techniques that work
 * - Target-specific patterns and behaviors
 */

export interface AttackAttempt {
	id: string
	timestamp: Date
	target: string
	attackType: string
	payload: string
	context: {
		endpoint: string
		parameter?: string
		technology: string
		wafSignature?: string
		cspPolicy?: string
	}
	result: "success" | "blocked" | "error" | "timeout"
	responseCode?: number
	errorMessage?: string
	responseTime: number
	bypassTechniques: string[]
}

export interface LearningPattern {
	id: string
	pattern: string
	confidence: number
	successRate: number
	applicableContexts: string[]
	lastUpdated: Date
	attempts: number
}

export interface TargetProfile {
	domain: string
	characteristics: {
		wafType?: string
		responsePatterns: string[]
		blockingKeywords: string[]
		successfulBypassTechniques: string[]
		averageResponseTime: number
		rateLimitThreshold?: number
		sessionHandling: string
	}
	vulnerabilityTypes: string[]
	lastUpdated: Date
}

export class AdaptiveLearning {
	private attempts: AttackAttempt[] = []
	private patterns: LearningPattern[] = []
	private targetProfiles: Map<string, TargetProfile> = new Map()
	private maxHistorySize = 10000 // Limit memory usage

	/**
	 * Record an attack attempt for learning
	 */
	recordAttempt(attempt: AttackAttempt): void {
		this.attempts.push(attempt)
		this.updateTargetProfile(attempt)
		this.updateLearningPatterns(attempt)

		// Cleanup old attempts to prevent memory bloat
		if (this.attempts.length > this.maxHistorySize) {
			this.attempts = this.attempts.slice(-this.maxHistorySize)
		}
	}

	/**
	 * Get recommendations for next attack based on learning
	 */
	getRecommendations(
		target: string,
		attackType: string,
		context: any,
	): {
		suggestedPayloads: string[]
		avoidPatterns: string[]
		bypassTechniques: string[]
		confidence: number
	} {
		const profile = this.getTargetProfile(target)
		const relevantAttempts = this.getRelevantAttempts(target, attackType, context)
		const successfulAttempts = relevantAttempts.filter((a) => a.result === "success")
		const blockedAttempts = relevantAttempts.filter((a) => a.result === "blocked")

		// Extract successful patterns
		const suggestedPayloads = this.extractSuccessfulPayloads(successfulAttempts)

		// Extract patterns to avoid
		const avoidPatterns = this.extractBlockedPatterns(blockedAttempts)

		// Get bypass techniques that work for this target
		const bypassTechniques = profile?.characteristics.successfulBypassTechniques || []

		// Calculate confidence based on data quality
		const confidence = this.calculateConfidence(relevantAttempts)

		return {
			suggestedPayloads,
			avoidPatterns,
			bypassTechniques,
			confidence,
		}
	}

	/**
	 * Predict if an attack is likely to succeed
	 */
	predictSuccess(
		target: string,
		payload: string,
		context: any,
	): {
		probability: number
		reasoning: string[]
		suggestions: string[]
	} {
		const profile = this.getTargetProfile(target)
		const reasoning: string[] = []
		const suggestions: string[] = []
		let probability = 0.5 // Base probability

		// Check against known blocking patterns
		if (profile) {
			for (const blockingKeyword of profile.characteristics.blockingKeywords) {
				if (payload.toLowerCase().includes(blockingKeyword.toLowerCase())) {
					probability -= 0.3
					reasoning.push(`Payload contains known blocking keyword: ${blockingKeyword}`)
					suggestions.push(`Try encoding or obfuscating: ${blockingKeyword}`)
				}
			}

			// Check successful bypass techniques
			for (const technique of profile.characteristics.successfulBypassTechniques) {
				if (this.payloadUsestechnique(payload, technique)) {
					probability += 0.2
					reasoning.push(`Payload uses successful technique: ${technique}`)
				}
			}
		}

		// Check against learned patterns
		for (const pattern of this.patterns) {
			if (this.payloadMatchesPattern(payload, pattern.pattern)) {
				if (pattern.successRate > 0.7) {
					probability += 0.15 * pattern.confidence
					reasoning.push(`Matches high-success pattern: ${pattern.pattern}`)
				} else if (pattern.successRate < 0.3) {
					probability -= 0.15 * pattern.confidence
					reasoning.push(`Matches low-success pattern: ${pattern.pattern}`)
					suggestions.push(`Consider modifying approach, this pattern fails often`)
				}
			}
		}

		// Ensure probability stays within bounds
		probability = Math.max(0, Math.min(1, probability))

		return {
			probability,
			reasoning,
			suggestions,
		}
	}

	/**
	 * Get adaptive delay recommendation to avoid rate limiting
	 */
	getOptimalDelay(target: string): number {
		const profile = this.getTargetProfile(target)
		if (!profile) {
			return 1000
		} // Default 1 second

		const recentAttempts = this.attempts.filter((a) => a.target === target).slice(-50) // Last 50 attempts

		// Check for rate limiting patterns
		const timeoutAttempts = recentAttempts.filter((a) => a.result === "timeout")
		if (timeoutAttempts.length > 5) {
			return Math.min(5000, profile.characteristics.averageResponseTime * 3)
		}

		// Adaptive delay based on success rate
		const successRate = recentAttempts.filter((a) => a.result === "success").length / recentAttempts.length
		if (successRate < 0.2) {
			return Math.min(3000, profile.characteristics.averageResponseTime * 2)
		}

		return Math.max(500, profile.characteristics.averageResponseTime)
	}

	/**
	 * Learn from similar targets to improve cold-start performance
	 */
	getKnowledgeTransfer(newTarget: string): {
		similarTargets: string[]
		transferablePatterns: LearningPattern[]
		recommendations: string[]
	} {
		const domain = new URL(newTarget).hostname
		const similarTargets: string[] = []
		const transferablePatterns: LearningPattern[] = []
		const recommendations: string[] = []

		// Find targets with similar characteristics
		for (const [targetDomain, profile] of this.targetProfiles) {
			if (this.areTargetsSimilar(domain, targetDomain)) {
				similarTargets.push(targetDomain)

				// Transfer successful techniques
				recommendations.push(
					...profile.characteristics.successfulBypassTechniques.map(
						(t) => `Try ${t} (successful on similar target: ${targetDomain})`,
					),
				)
			}
		}

		// Get high-confidence patterns that might transfer
		transferablePatterns.push(
			...this.patterns.filter((p) => p.confidence > 0.8 && p.successRate > 0.6 && p.applicableContexts.includes("generic")),
		)

		return {
			similarTargets,
			transferablePatterns,
			recommendations,
		}
	}

	/**
	 * Export learning data for analysis and backup
	 */
	exportLearningData(): {
		attempts: AttackAttempt[]
		patterns: LearningPattern[]
		targetProfiles: Record<string, TargetProfile>
		statistics: {
			totalAttempts: number
			successRate: number
			mostSuccessfulTechniques: string[]
			commonBlockingPatterns: string[]
		}
	} {
		const statistics = this.generateStatistics()

		return {
			attempts: this.attempts,
			patterns: this.patterns,
			targetProfiles: Object.fromEntries(this.targetProfiles),
			statistics,
		}
	}

	/**
	 * Import learning data from previous sessions
	 */
	importLearningData(data: any): void {
		if (data.attempts) {
			this.attempts = data.attempts.map((a: any) => ({
				...a,
				timestamp: new Date(a.timestamp),
			}))
		}

		if (data.patterns) {
			this.patterns = data.patterns.map((p: any) => ({
				...p,
				lastUpdated: new Date(p.lastUpdated),
			}))
		}

		if (data.targetProfiles) {
			this.targetProfiles = new Map(
				Object.entries(data.targetProfiles).map(([k, v]: [string, any]) => [
					k,
					{ ...v, lastUpdated: new Date(v.lastUpdated) },
				]),
			)
		}
	}

	// Private helper methods
	private updateTargetProfile(attempt: AttackAttempt): void {
		const domain = new URL(attempt.target).hostname
		let profile = this.targetProfiles.get(domain)

		if (!profile) {
			profile = {
				domain,
				characteristics: {
					responsePatterns: [],
					blockingKeywords: [],
					successfulBypassTechniques: [],
					averageResponseTime: attempt.responseTime,
					sessionHandling: "unknown",
				},
				vulnerabilityTypes: [],
				lastUpdated: new Date(),
			}
		}

		// Update response time average
		profile.characteristics.averageResponseTime = (profile.characteristics.averageResponseTime + attempt.responseTime) / 2

		// Learn from blocked attempts
		if (attempt.result === "blocked" && attempt.errorMessage) {
			const keywords = this.extractBlockingKeywords(attempt.payload, attempt.errorMessage)
			profile.characteristics.blockingKeywords.push(...keywords)
		}

		// Learn from successful attempts
		if (attempt.result === "success") {
			profile.characteristics.successfulBypassTechniques.push(...attempt.bypassTechniques)
			if (!profile.vulnerabilityTypes.includes(attempt.attackType)) {
				profile.vulnerabilityTypes.push(attempt.attackType)
			}
		}

		// Detect WAF type
		if (attempt.context.wafSignature && !profile.characteristics.wafType) {
			profile.characteristics.wafType = attempt.context.wafSignature
		}

		profile.lastUpdated = new Date()
		this.targetProfiles.set(domain, profile)
	}

	private updateLearningPatterns(attempt: AttackAttempt): void {
		const payloadPattern = this.extractPattern(attempt.payload)
		let pattern = this.patterns.find((p) => p.pattern === payloadPattern)

		if (!pattern) {
			pattern = {
				id: `pattern_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
				pattern: payloadPattern,
				confidence: 0.1,
				successRate: 0,
				applicableContexts: [attempt.context.technology],
				lastUpdated: new Date(),
				attempts: 0,
			}
			this.patterns.push(pattern)
		}

		pattern.attempts++
		const successCount = this.attempts.filter(
			(a) => this.payloadMatchesPattern(a.payload, pattern!.pattern) && a.result === "success",
		).length

		pattern.successRate = successCount / pattern.attempts
		pattern.confidence = Math.min(1, pattern.attempts / 10) // Confidence builds with attempts
		pattern.lastUpdated = new Date()

		// Add context if not present
		if (!pattern.applicableContexts.includes(attempt.context.technology)) {
			pattern.applicableContexts.push(attempt.context.technology)
		}
	}

	private getTargetProfile(target: string): TargetProfile | undefined {
		const domain = new URL(target).hostname
		return this.targetProfiles.get(domain)
	}

	private getRelevantAttempts(target: string, attackType: string, context: any): AttackAttempt[] {
		const domain = new URL(target).hostname
		return this.attempts.filter((a) => {
			const attemptDomain = new URL(a.target).hostname
			return attemptDomain === domain && a.attackType === attackType && a.context.technology === context.technology
		})
	}

	private extractSuccessfulPayloads(attempts: AttackAttempt[]): string[] {
		return [...new Set(attempts.map((a) => a.payload))].slice(0, 5) // Top 5 unique successful payloads
	}

	private extractBlockedPatterns(attempts: AttackAttempt[]): string[] {
		const patterns = new Set<string>()
		attempts.forEach((a) => {
			// Extract common patterns from blocked payloads
			const commonPatterns = ["<script", "alert(", "javascript:", "onerror=", "onload="]
			commonPatterns.forEach((pattern) => {
				if (a.payload.toLowerCase().includes(pattern)) {
					patterns.add(pattern)
				}
			})
		})
		return Array.from(patterns)
	}

	private calculateConfidence(attempts: AttackAttempt[]): number {
		if (attempts.length === 0) {
			return 0
		}
		if (attempts.length < 5) {
			return 0.3
		}
		if (attempts.length < 20) {
			return 0.6
		}
		return 0.9
	}

	private payloadUsestechnique(payload: string, technique: string): boolean {
		const techniquePatterns: Record<string, string[]> = {
			encoding: ["%", "&#", "\\u", "\\x"],
			obfuscation: ["eval", "unescape", "fromCharCode"],
			event_handler: ["on", "onerror", "onload", "onmouseover"],
			protocol_injection: ["javascript:", "data:", "vbscript:"],
			attribute_breakout: ['"', "'", "`"],
		}

		const patterns = techniquePatterns[technique] || []
		return patterns.some((pattern) => payload.includes(pattern))
	}

	private payloadMatchesPattern(payload: string, pattern: string): boolean {
		// Simple pattern matching - could be enhanced with regex
		return payload.toLowerCase().includes(pattern.toLowerCase())
	}

	private extractPattern(payload: string): string {
		// Extract key pattern from payload (simplified)
		const patterns = ["<script", "alert(", "onerror=", "UNION", "SELECT", "../../"]
		for (const pattern of patterns) {
			if (payload.toLowerCase().includes(pattern.toLowerCase())) {
				return pattern
			}
		}
		return payload.substring(0, 20) // Fallback to first 20 chars
	}

	private extractBlockingKeywords(payload: string, errorMessage: string): string[] {
		const keywords: string[] = []

		// Common WAF blocking indicators
		const wafKeywords = ["blocked", "forbidden", "security", "malicious", "attack"]
		wafKeywords.forEach((keyword) => {
			if (errorMessage.toLowerCase().includes(keyword)) {
				// Try to find what specific part of payload triggered it
				const payloadWords = payload.split(/\W+/).filter((w) => w.length > 2)
				keywords.push(...payloadWords.slice(0, 3)) // First few words likely triggered it
			}
		})

		return keywords
	}

	private areTargetsSimilar(domain1: string, domain2: string): boolean {
		// Simple similarity check - could be enhanced
		const tld1 = domain1.split(".").pop()
		const tld2 = domain2.split(".").pop()

		// Same TLD or similar domain structure
		return tld1 === tld2 || domain1.includes(domain2.split(".")[0]) || domain2.includes(domain1.split(".")[0])
	}

	private generateStatistics(): any {
		const totalAttempts = this.attempts.length
		const successfulAttempts = this.attempts.filter((a) => a.result === "success").length
		const successRate = totalAttempts > 0 ? successfulAttempts / totalAttempts : 0

		// Most successful techniques
		const techniqueCount = new Map<string, number>()
		this.attempts.forEach((a) => {
			if (a.result === "success") {
				a.bypassTechniques.forEach((t) => {
					techniqueCount.set(t, (techniqueCount.get(t) || 0) + 1)
				})
			}
		})

		const mostSuccessfulTechniques = Array.from(techniqueCount.entries())
			.sort(([, a], [, b]) => b - a)
			.slice(0, 5)
			.map(([technique]) => technique)

		// Common blocking patterns
		const blockingPatterns = new Map<string, number>()
		this.attempts.forEach((a) => {
			if (a.result === "blocked") {
				const pattern = this.extractPattern(a.payload)
				blockingPatterns.set(pattern, (blockingPatterns.get(pattern) || 0) + 1)
			}
		})

		const commonBlockingPatterns = Array.from(blockingPatterns.entries())
			.sort(([, a], [, b]) => b - a)
			.slice(0, 5)
			.map(([pattern]) => pattern)

		return {
			totalAttempts,
			successRate,
			mostSuccessfulTechniques,
			commonBlockingPatterns,
		}
	}
}
