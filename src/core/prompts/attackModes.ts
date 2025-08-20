export type AttackModeId =
	| "baseline"
	| "javascript_intel"
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

const mode = (title: string, bullets: string[]): string =>
	[`### Attack Mode: ${title}`, ...bullets.map((b) => `- ${b}`), ""].join("\n")

export const attackModePrompts: Record<AttackModeId, string> = {
	baseline: mode("Baseline", [
		"Start with low-noise validation of common classes: XSS, SQLi, IDOR, SSRF, file upload, LFI/RFI, auth logic.",
		"Prefer parameter harvesting and differential responses to guide hypotheses.",
	]),
	javascript_intel: mode("JavaScript Intelligence", [
		"Crawl and fetch front-end JS aggressively (respecting scope). Save artifacts under docs/pentest/artifacts/js/ and index them.",
		"Extract API base URLs, routes, query param names, GraphQL endpoints, WebSocket URLs, feature flags, debug toggles, admin paths.",
		"Look for source maps (.map), bundled config (window.__env__, __NEXT_DATA__, __NUXT__); parse for secrets, keys, and internal hosts.",
		"Map framework routers (React/Next.js, Vue/Nuxt, Angular) to enumerate hidden pages, admin panels, and API handlers.",
	]),
	xss: mode("Cross-Site Scripting (XSS)", [
		"Probe reflection points, contexts (HTML, attribute, JS, URL, SVG).",
		"Evasion: event handlers, srcdoc, template injection; encode-breaking payloads; CSP-aware vectors.",
		"DOM-XSS: sink discovery via quick JS grep (location, innerHTML, document.write, jQuery).",
		"If CSP is present, shift to 'csp_bypass' mode and attempt nonce/leakage/JSONP/inline style escapes.",
	]),
	sqli: mode("SQL Injection (SQLi)", [
		"Error-based, boolean/time-based, stacked queries where viable; fingerprint DB (MySQL, Postgres, MSSQL, Oracle).",
		"Focus on auth endpoints, search, sort, filter, and bulk operations.",
	]),
	idor: mode("IDOR/BOLA", [
		"Adjust identifiers (sequential, UUIDs across tenants), fuzz object references and collection filters.",
		"Check privilege boundaries with minimal noise; attempt vertical and horizontal access tests.",
	]),
	ssrf: mode("SSRF", [
		"Identify URL fetchers, webhooks, image/pdf fetch endpoints; try internal IPs and metadata services.",
		"Use DNS canary endpoints and request smuggling patterns if applicable.",
	]),
	lfi_rfi: mode("LFI/RFI", ["Probe file path parameters; try traversal, null byte, stream wrappers, filter chains."]),
	command_injection: mode("Command Injection", [
		"Look for OS command wrappers, ping/curl utilities, and serialization to shell contexts.",
	]),
	auth_bypass: mode("Auth/Session/CSRF", [
		"JWT alg=none/signature confusion, cookie flags, CSRF on state-changing endpoints, weak password flows.",
	]),
	upload_bypass: mode("File Upload Bypass", [
		"Extension/double-extension tricks, content-type mismatches, polyglots; storage path traversal.",
	]),
	deserialization: mode("Insecure Deserialization", [
		"Language-specific gadget chains; signed object tampering; compressed payload tricks.",
	]),
	jwt: mode("JWT Attacks", ["Key guessing, alg confusion, kid header path traversal, JWK supply, jwk-set-url SSRF."]),
	waf_bypass: mode("WAF Bypass", [
		"Apply encoder/obfuscation rotations, case/spacing tweaks, JSON-in-JSON, mixed encodings, path normalization.",
		"Vendor-specific quirks if vendor is known (Akamai/Cloudflare/Imperva/F5).",
	]),
	csp_bypass: mode("CSP Bypass", [
		"Analyze directives; attempt nonce reuse/leak, JSONP endpoints, strict-dynamic pitfalls, data: and blob: vectors.",
	]),
}

export function buildAttackModeSection(
	currentMode?: string,
	detections?: {
		wafVendorOrSignal?: string
		cspPolicySnippet?: string
		rateLimitingObserved?: boolean
	},
): string {
	const id = (currentMode as AttackModeId) || "baseline"
	const section = attackModePrompts[id]
	const signals = [
		detections?.wafVendorOrSignal ? `WAF signal: ${detections.wafVendorOrSignal}` : undefined,
		detections?.cspPolicySnippet ? `CSP: ${detections.cspPolicySnippet}` : undefined,
		detections?.rateLimitingObserved !== undefined ? `Rate limiting observed: ${detections.rateLimitingObserved}` : undefined,
	]
		.filter(Boolean)
		.join("\n")

	const signalsBlock = signals ? `\n\nSignals\n- ${signals.split("\n").join("\n- ")}` : ""
	return `\n\n====\n\nMODE ROUTING\n\n${section}${signalsBlock}`
}
