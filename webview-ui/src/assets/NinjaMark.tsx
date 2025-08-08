import React from "react"

const NinjaMark: React.FC<React.SVGProps<SVGSVGElement>> = (props) => (
	<svg
		width={props.width || 92}
		height={props.height || 92}
		viewBox="0 0 92 92"
		fill="none"
		xmlns="http://www.w3.org/2000/svg"
		{...props}>
		<defs>
			<linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
				<stop offset="0%" stopColor="#00ffff" />
				<stop offset="100%" stopColor="#0ea5e9" />
			</linearGradient>
		</defs>
		{/* stylized hood */}
		<path d="M46 8c15 0 30 11 30 28 0 10-4 18-10 24H26C20 54 16 46 16 36 16 19 31 8 46 8Z" fill="#0f172a" stroke="#1e293b" />
		{/* eyes */}
		<ellipse cx="34" cy="36" rx="5" ry="7" fill="url(#g)" />
		<ellipse cx="58" cy="36" rx="5" ry="7" fill="url(#g)" />
		{/* mask */}
		<path d="M28 44c12 6 24 6 36 0-4 9-12 12-18 12S32 53 28 44Z" fill="#0a0a0f" stroke="#334155" />
		{/* sword */}
		<path d="M70 18l-2 6-28 28-6 2 2-6 28-28 6-2Z" fill="#0ea5e9" />
	</svg>
)

export default NinjaMark
