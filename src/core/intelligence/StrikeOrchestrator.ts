/**
 * StrikeOrchestrator - Master orchestration system for elite-level pentesting
 *
 * This is the brain of the STRIKE intelligence system that coordinates:
 * - Intelligent reconnaissance
 * - Adaptive payload generation
 * - Vulnerability chaining
 * - Learning from failures
 * - Strategic attack planning
 */

import { ReconOrchestrator, ReconIntelligence } from "./ReconOrchestrator"
import { PayloadEngine, PayloadContext, GeneratedPayload } from "./PayloadEngine"
import { VulnerabilityChainer, Finding, AttackChain } from "./VulnerabilityChainer"
import { AdaptiveLearning, AttackAttempt } from "./AdaptiveLearning"
import { DocumentationService } from "@/core/pentest/DocumentationService"
import { ToolExecutor } from "@/core/task/ToolExecutor"
export type AttackMode =
	| "baseline"
	| "xss"
	| "sqli"
	| "idor"
	| "ssrf"
	| "lfi_rfi"
	| "command_injection"
	| "auth_bypass"
	| "upload_bypass"
	| "deserialization"
	| "jwt"
	| "waf_bypass"
	| "csp_bypass"
	| "javascript_intel"

export interface StrikeSession {
	id: string
	target: string
	startTime: Date
	currentPhase: "recon" | "analysis" | "exploitation" | "chaining" | "reporting"
	intelligence: ReconIntelligence | null
	findings: Finding[]
	attackChains: AttackChain[]
	currentStrategy: AttackStrategy
}

export interface AttackStrategy {
	primaryMode: AttackMode
	secondaryModes: AttackMode[]
	reasoning: string
	expectedImpact: string
	riskLevel: "low" | "medium" | "high"
	estimatedTime: number
	prerequisites: string[]
}

export class StrikeOrchestrator {
	private reconOrchestrator: ReconOrchestrator
	private payloadEngine: PayloadEngine
	private vulnerabilityChainer: VulnerabilityChainer
	private adaptiveLearning: AdaptiveLearning
	private doc: DocumentationService
	private toolExecutor: ToolExecutor
	private currentSession: StrikeSession | null = null

	constructor(cwd: string, toolExecutor: ToolExecutor) {
		this.toolExecutor = toolExecutor
		this.doc = new DocumentationService(cwd)
		this.reconOrchestrator = new ReconOrchestrator(cwd, toolExecutor)
		this.payloadEngine = new PayloadEngine()
		this.vulnerabilityChainer = new VulnerabilityChainer()
		this.adaptiveLearning = new AdaptiveLearning()

		// Load previous learning data if available
		this.loadLearningData()
	}

	/**
	 * Start a new STRIKE penetration testing session
	 */
	async startSession(target: string): Promise<StrikeSession> {
		const session: StrikeSession = {
			id: `strike_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
			target,
			startTime: new Date(),
			currentPhase: "recon",
			intelligence: null,
			findings: [],
			attackChains: [],
			currentStrategy: {
				primaryMode: "baseline",
				secondaryModes: [],
				reasoning: "Initial baseline assessment",
				expectedImpact: "Discovery of basic vulnerabilities",
				riskLevel: "low",
				estimatedTime: 30,
				prerequisites: [],
			},
		}

		this.currentSession = session

		await this.doc.appendJournal({
			phase: "STRIKE_ORCHESTRATION",
			action: "session_start",
			resultSummary: `Started STRIKE session for ${target}`,
			command: `StrikeOrchestrator.startSession(${target})`,
		})

		// Execute intelligent reconnaissance
		await this.executeIntelligentRecon()

		return session
	}

	/**
	 * Execute the complete STRIKE methodology
	 */
	async executeStrikeMethodology(): Promise<void> {
		if (!this.currentSession) {
			throw new Error("No active STRIKE session")
		}

		try {
			// Phase 1: Intelligent Reconnaissance
			await this.executeIntelligentRecon()

			// Phase 2: Strategic Analysis & Planning
			await this.executeStrategicAnalysis()

			// Phase 3: Adaptive Exploitation
			await this.executeAdaptiveExploitation()

			// Phase 4: Vulnerability Chaining
			await this.executeVulnerabilityChaining()

			// Phase 5: Impact Assessment & Reporting
			await this.generateStrikeReport()
		} catch (error) {
			await this.handleStrikeError(error)
		}
	}

	/**
	 * Get current session
	 */
	getCurrentSession(): StrikeSession | null {
		return this.currentSession
	}

	/**
	 * Get intelligent attack recommendations based on current intelligence
	 */
	getIntelligentRecommendations(): {
		recommendedMode: AttackMode
		reasoning: string[]
		payloadSuggestions: GeneratedPayload[]
		chainOpportunities: AttackChain[]
		confidence: number
	} {
		if (!this.currentSession?.intelligence) {
			return {
				recommendedMode: "baseline",
				reasoning: ["No intelligence available, starting with baseline"],
				payloadSuggestions: [],
				chainOpportunities: [],
				confidence: 0,
			}
		}

		const intel = this.currentSession.intelligence
		const reasoning: string[] = []
		let recommendedMode: AttackMode = "baseline"
		let confidence = 0.5

		// Analyze intelligence to recommend attack mode
		if (intel.jsFiles.length > 5) {
			recommendedMode = "javascript_intel"
			reasoning.push(`${intel.jsFiles.length} JavaScript files detected - high potential for endpoint discovery`)
			confidence += 0.2
		}

		if (intel.csp) {
			if (recommendedMode === "baseline") {
				recommendedMode = "csp_bypass"
			}
			reasoning.push("CSP detected - bypass techniques required for XSS")
			confidence += 0.15
		}

		if (intel.techStack.waf) {
			reasoning.push(`WAF detected (${intel.techStack.waf}) - evasion techniques required`)
			confidence += 0.1
		}

		if (intel.attackSurface.authEndpoints.length > 0) {
			if (recommendedMode === "baseline") {
				recommendedMode = "auth_bypass"
			}
			reasoning.push(`${intel.attackSurface.authEndpoints.length} authentication endpoints found`)
			confidence += 0.15
		}

		// Get payload suggestions for recommended mode
		const payloadSuggestions = this.generateContextualPayloads(recommendedMode, intel)

		// Get chain opportunities
		const chainOpportunities = this.vulnerabilityChainer.getHighImpactChains()

		return {
			recommendedMode,
			reasoning,
			payloadSuggestions,
			chainOpportunities,
			confidence: Math.min(1, confidence),
		}
	}

	/**
	 * Record attack attempt for learning
	 */
	recordAttackAttempt(
		payload: string,
		result: "success" | "blocked" | "error" | "timeout",
		context: any,
		responseCode?: number,
		errorMessage?: string,
		responseTime: number = 1000,
	): void {
		if (!this.currentSession) {
			return
		}

		const attempt: AttackAttempt = {
			id: `attempt_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
			timestamp: new Date(),
			target: this.currentSession.target,
			attackType: this.currentSession.currentStrategy.primaryMode,
			payload,
			context: {
				endpoint: context.endpoint || "",
				parameter: context.parameter,
				technology: this.currentSession.intelligence?.techStack.framework || "unknown",
				wafSignature: this.currentSession.intelligence?.techStack.waf,
				cspPolicy: this.currentSession.intelligence?.csp,
			},
			result,
			responseCode,
			errorMessage,
			responseTime,
			bypassTechniques: context.bypassTechniques || [],
		}

		this.adaptiveLearning.recordAttempt(attempt)

		// Learn from the attempt
		if (result === "success") {
			const payloadContext: PayloadContext = {
				technology: attempt.context.technology,
				wafSignature: attempt.context.wafSignature,
				cspPolicy: attempt.context.cspPolicy,
				previousFailures: [],
				targetEndpoint: attempt.context.endpoint,
				injectionContext: "html",
			}
			this.payloadEngine.recordSuccess(payload, payloadContext)
		} else if (result === "blocked" && errorMessage) {
			const payloadContext: PayloadContext = {
				technology: attempt.context.technology,
				wafSignature: attempt.context.wafSignature,
				cspPolicy: attempt.context.cspPolicy,
				previousFailures: [],
				targetEndpoint: attempt.context.endpoint,
				injectionContext: "html",
			}
			this.payloadEngine.recordFailure(payload, payloadContext, errorMessage)
		}
	}

	/**
	 * Add a new finding and analyze for chains
	 */
	addFinding(finding: Finding): void {
		if (!this.currentSession) {
			return
		}

		this.currentSession.findings.push(finding)
		this.vulnerabilityChainer.addFinding(finding)

		// Update attack chains
		this.currentSession.attackChains = this.vulnerabilityChainer.getAttackChains()

		// Log the finding
		this.doc.appendJournal({
			phase: "EXPLOITATION",
			action: "finding_discovered",
			resultSummary: `${finding.type.toUpperCase()}: ${finding.description}`,
			command: `Finding: ${finding.endpoint}`,
		})
	}

	// Private implementation methods
	private async executeIntelligentRecon(): Promise<void> {
		if (!this.currentSession) {
			return
		}

		this.currentSession.currentPhase = "recon"

		await this.doc.appendJournal({
			phase: "STRIKE_RECON",
			action: "intelligent_recon_start",
			resultSummary: "Starting STRIKE intelligent reconnaissance",
			command: "StrikeOrchestrator.executeIntelligentRecon()",
		})

		// Execute comprehensive recon
		const intelligence = await this.reconOrchestrator.executeIntelligentRecon(this.currentSession.target)
		this.currentSession.intelligence = intelligence

		// Apply knowledge transfer from similar targets
		const transfer = this.adaptiveLearning.getKnowledgeTransfer(this.currentSession.target)
		if (transfer.recommendations.length > 0) {
			await this.doc.appendRecon([
				"## Knowledge Transfer",
				"Applying lessons learned from similar targets:",
				...transfer.recommendations.map((r) => `- ${r}`),
			])
		}
	}

	private async executeStrategicAnalysis(): Promise<void> {
		if (!this.currentSession) {
			return
		}

		this.currentSession.currentPhase = "analysis"

		const recommendations = this.getIntelligentRecommendations()

		// Update strategy based on intelligence
		this.currentSession.currentStrategy = {
			primaryMode: recommendations.recommendedMode,
			secondaryModes: this.deriveSecondaryModes(recommendations.recommendedMode),
			reasoning: recommendations.reasoning.join("; "),
			expectedImpact: this.estimateImpact(recommendations.recommendedMode),
			riskLevel: this.assessRiskLevel(recommendations.recommendedMode),
			estimatedTime: this.estimateTime(recommendations.recommendedMode),
			prerequisites: [],
		}

		await this.doc.appendJournal({
			phase: "STRIKE_ANALYSIS",
			action: "strategy_selected",
			resultSummary: `Primary mode: ${recommendations.recommendedMode}, Confidence: ${recommendations.confidence}`,
			command: `Strategy: ${this.currentSession.currentStrategy.reasoning}`,
		})
	}

	private async executeAdaptiveExploitation(): Promise<void> {
		if (!this.currentSession) {
			return
		}

		this.currentSession.currentPhase = "exploitation"

		// This would integrate with the existing attack mode system
		// The ToolExecutor would use the STRIKE recommendations for smarter attacks

		await this.doc.appendJournal({
			phase: "STRIKE_EXPLOITATION",
			action: "adaptive_exploitation_start",
			resultSummary: `Starting adaptive exploitation with ${this.currentSession.currentStrategy.primaryMode} mode`,
			command: "StrikeOrchestrator.executeAdaptiveExploitation()",
		})
	}

	private async executeVulnerabilityChaining(): Promise<void> {
		if (!this.currentSession) {
			return
		}

		this.currentSession.currentPhase = "chaining"

		const highImpactChains = this.vulnerabilityChainer.getHighImpactChains()

		if (highImpactChains.length > 0) {
			await this.doc.appendJournal({
				phase: "STRIKE_CHAINING",
				action: "chains_identified",
				resultSummary: `Identified ${highImpactChains.length} high-impact attack chains`,
				command: "VulnerabilityChainer.getHighImpactChains()",
			})

			// Generate exploit scripts for top chains
			for (const chain of highImpactChains.slice(0, 3)) {
				const script = this.vulnerabilityChainer.generateExploitScript(chain.id)
				await this.doc.saveArtifact(`exploit_${chain.id}.py`, script)
			}
		}
	}

	private async generateStrikeReport(): Promise<void> {
		if (!this.currentSession) {
			return
		}

		this.currentSession.currentPhase = "reporting"

		const report = this.vulnerabilityChainer.exportReport()
		const learningData = this.adaptiveLearning.exportLearningData()

		const strikeReport = [
			"# STRIKE Penetration Testing Report",
			"",
			`**Target:** ${this.currentSession.target}`,
			`**Session ID:** ${this.currentSession.id}`,
			`**Duration:** ${this.calculateSessionDuration()}`,
			"",
			"## Executive Summary",
			report.summary,
			"",
			"## Intelligence Gathered",
			`- Technology Stack: ${this.currentSession.intelligence?.techStack.framework || "Unknown"}`,
			`- Endpoints Discovered: ${this.currentSession.intelligence?.endpoints.length || 0}`,
			`- JavaScript Files: ${this.currentSession.intelligence?.jsFiles.length || 0}`,
			`- API Routes: ${this.currentSession.intelligence?.apiRoutes.length || 0}`,
			"",
			"## Attack Strategy",
			`**Primary Mode:** ${this.currentSession.currentStrategy.primaryMode}`,
			`**Reasoning:** ${this.currentSession.currentStrategy.reasoning}`,
			`**Risk Level:** ${this.currentSession.currentStrategy.riskLevel}`,
			"",
			"## Findings",
			...this.currentSession.findings.map((f) => `- **${f.type.toUpperCase()}** (${f.severity}): ${f.description}`),
			"",
			"## Attack Chains",
			...report.chains.map((c) => `- **${c.name}** (${c.overallSeverity}): ${c.finalImpact}`),
			"",
			"## Learning Statistics",
			`- Total Attack Attempts: ${learningData.statistics.totalAttempts}`,
			`- Success Rate: ${(learningData.statistics.successRate * 100).toFixed(1)}%`,
			`- Most Successful Techniques: ${learningData.statistics.mostSuccessfulTechniques.join(", ")}`,
			"",
			"## Recommendations",
			...report.recommendations,
			"",
			"---",
			"*Generated by STRIKE Orchestrator*",
		]

		await this.doc.saveArtifact("strike_report.md", strikeReport.join("\n"))

		// Save learning data for future sessions
		await this.saveLearningData()
	}

	private generateContextualPayloads(mode: AttackMode, intel: ReconIntelligence): GeneratedPayload[] {
		const context: PayloadContext = {
			technology: intel.techStack.framework || "unknown",
			wafSignature: intel.techStack.waf,
			cspPolicy: intel.csp,
			previousFailures: [],
			targetEndpoint: intel.target.url,
			injectionContext: "html",
		}

		switch (mode) {
			case "xss":
				return this.payloadEngine.generateXSSPayloads(context)
			case "sqli":
				return this.payloadEngine.generateSQLiPayloads(context)
			case "ssrf":
				return this.payloadEngine.generateSSRFPayloads(context)
			default:
				return []
		}
	}

	private deriveSecondaryModes(primaryMode: AttackMode): AttackMode[] {
		const modeMap: Record<AttackMode, AttackMode[]> = {
			javascript_intel: ["xss", "idor"],
			xss: ["csp_bypass", "javascript_intel"],
			auth_bypass: ["idor", "sqli"],
			csp_bypass: ["xss", "javascript_intel"],
			baseline: ["xss", "sqli", "idor"],
			sqli: ["auth_bypass", "idor"],
			idor: ["auth_bypass", "sqli"],
			ssrf: ["idor", "lfi_rfi"],
			lfi_rfi: ["ssrf", "command_injection"],
			command_injection: ["lfi_rfi", "upload_bypass"],
			upload_bypass: ["command_injection", "xss"],
			deserialization: ["command_injection", "sqli"],
			jwt: ["auth_bypass", "idor"],
			waf_bypass: ["xss", "sqli"],
		}

		return modeMap[primaryMode] || []
	}

	private estimateImpact(mode: AttackMode): string {
		const impactMap: Record<AttackMode, string> = {
			auth_bypass: "Account takeover and unauthorized access",
			sqli: "Database compromise and data exfiltration",
			xss: "Session hijacking and client-side attacks",
			idor: "Unauthorized data access across accounts",
			ssrf: "Internal network access and service enumeration",
			javascript_intel: "Discovery of hidden attack surface",
			csp_bypass: "Circumvention of XSS protections",
			baseline: "Basic vulnerability assessment",
			lfi_rfi: "Local/remote file inclusion and code execution",
			command_injection: "Operating system command execution",
			upload_bypass: "Malicious file upload and execution",
			deserialization: "Object deserialization attacks",
			jwt: "JSON Web Token manipulation and bypass",
			waf_bypass: "Web Application Firewall evasion",
		}

		return impactMap[mode] || "Basic vulnerability assessment"
	}

	private assessRiskLevel(mode: AttackMode): "low" | "medium" | "high" {
		const riskMap: Record<AttackMode, "low" | "medium" | "high"> = {
			baseline: "low",
			javascript_intel: "low",
			xss: "medium",
			sqli: "high",
			auth_bypass: "high",
			idor: "medium",
			ssrf: "high",
			csp_bypass: "medium",
			lfi_rfi: "high",
			command_injection: "high",
			upload_bypass: "high",
			deserialization: "high",
			jwt: "medium",
			waf_bypass: "medium",
		}

		return riskMap[mode] || "low"
	}

	private estimateTime(mode: AttackMode): number {
		const timeMap: Record<AttackMode, number> = {
			baseline: 15,
			javascript_intel: 30,
			xss: 20,
			sqli: 45,
			auth_bypass: 30,
			idor: 25,
			ssrf: 40,
			csp_bypass: 35,
			lfi_rfi: 35,
			command_injection: 40,
			upload_bypass: 30,
			deserialization: 50,
			jwt: 25,
			waf_bypass: 30,
		}

		return timeMap[mode] || 20
	}

	private calculateSessionDuration(): string {
		if (!this.currentSession) {
			return "0 minutes"
		}

		const duration = Date.now() - this.currentSession.startTime.getTime()
		const minutes = Math.floor(duration / 60000)
		return `${minutes} minutes`
	}

	private async handleStrikeError(error: any): Promise<void> {
		await this.doc.appendJournal({
			phase: "STRIKE_ERROR",
			action: "error_handled",
			resultSummary: `STRIKE error: ${error.message}`,
			command: "StrikeOrchestrator.handleStrikeError()",
		})
	}

	private async loadLearningData(): Promise<void> {
		try {
			// This would load from persistent storage
			// For now, we'll skip the actual file I/O
		} catch (error) {
			// Learning data not available, starting fresh
		}
	}

	private async saveLearningData(): Promise<void> {
		try {
			const data = this.adaptiveLearning.exportLearningData()
			await this.doc.saveArtifact("strike_learning_data.json", JSON.stringify(data, null, 2))
		} catch (error) {
			console.error("Failed to save learning data:", error)
		}
	}
}
