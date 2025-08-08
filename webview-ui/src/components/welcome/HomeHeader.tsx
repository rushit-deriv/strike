import HeroTooltip from "@/components/common/HeroTooltip"
import { UiServiceClient } from "@/services/grpc-client"
import { EmptyRequest } from "@shared/proto/cline/common"
import NinjaInlineIcon from "@/assets/NinjaInlineIcon"

interface HomeHeaderProps {
	shouldShowQuickWins?: boolean
}

const HomeHeader = ({ shouldShowQuickWins = false }: HomeHeaderProps) => {
	const handleTakeATour = async () => {
		try {
			await UiServiceClient.openWalkthrough(EmptyRequest.create())
		} catch (error) {
			console.error("Error opening walkthrough:", error)
		}
	}

	return (
		<div className="flex flex-col items-center mb-5">
			<div className="my-5">
				<NinjaInlineIcon width={64} height={64} />
			</div>
			<div className="text-center flex items-center justify-center">
				<h2 className="m-0 text-[var(--vscode-font-size)]">{"What can I attack for you?"}</h2>
				<HeroTooltip
					placement="bottom"
					className="max-w-[300px]"
					content={
						"Strike performs recon-first, stealthy testing. It uses CLI tools and the browser efficiently (when it adds clear value), and logs every attempt to markdown for a full audit trail."
					}>
					<span
						className="codicon codicon-info ml-2 cursor-pointer"
						style={{ fontSize: "14px", color: "var(--vscode-textLink-foreground)" }}
					/>
				</HeroTooltip>
			</div>
			{shouldShowQuickWins && (
				<div className="mt-4">
					<button
						onClick={handleTakeATour}
						className="flex items-center gap-2 px-4 py-2 rounded-full border border-[var(--vscode-panel-border)] bg-white/[0.02] hover:bg-[var(--vscode-list-hoverBackground)] transition-colors duration-150 ease-in-out text-[var(--vscode-editor-foreground)] text-sm font-medium cursor-pointer">
						Take a Tour
						<span className="codicon codicon-play scale-90"></span>
					</button>
				</div>
			)}
		</div>
	)
}

export default HomeHeader
