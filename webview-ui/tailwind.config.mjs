import { heroui } from "@heroui/react"

/** @type {import('tailwindcss').Config} */
const config = {
	content: ["./src/**/*.{js,ts,jsx,tsx,mdx}", "./node_modules/@heroui/theme/dist/**/*.{js,ts,jsx,tsx}"],
	theme: {
		extend: {
			fontFamily: {
				"azeret-mono": ['"Azeret Mono"', "monospace"],
			},
			colors: {
				strike: {
					primary: "#0f172a", // Deep dark blue
					secondary: "#1e293b", // Medium dark blue
					accent: "#00d4ff", // Cyan glow
					"accent-dim": "#0ea5e9", // Dimmer cyan
					danger: "#ef4444", // Red alerts
					success: "#10b981", // Green success
					text: "#f1f5f9", // Light text
					"text-dim": "#94a3b8", // Dimmed text
					border: "#334155", // Borders
					hover: "#0f1629", // Hover states
				},
			},
		},
	},
	darkMode: "class",
	plugins: [
		heroui({
			defaultTheme: "vscode",
			themes: {
				vscode: {
					colors: {
						background: "",
					},
				},
			},
		}),
	],
}
export default config
