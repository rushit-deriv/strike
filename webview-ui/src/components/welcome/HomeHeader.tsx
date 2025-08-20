import { EmptyRequest } from "@shared/proto/cline/common"
import NinjaInlineIcon from "@/assets/NinjaInlineIcon"
import HeroTooltip from "@/components/common/HeroTooltip"
import { UiServiceClient } from "@/services/grpc-client"

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
				<h2 className="m-0 text-lg">{"What can I attack for you?"}</h2>
				<HeroTooltip
					className="max-w-[300px]"
					content={
						"Strike performs recon-first, stealthy testing. It uses CLI tools and the browser efficiently (when it adds clear value), and logs every attempt to markdown for a full audit trail."
					}
					placement="bottom">
					<span className="codicon codicon-info ml-2 cursor-pointer text-link text-sm" />
				</HeroTooltip>
			</div>
			{shouldShowQuickWins && (
				<div className="mt-4">
					<button
						className="flex items-center gap-2 px-4 py-2 rounded-full border border-border-panel bg-white/[0.02] hover:bg-list-background-hover transition-colors duration-150 ease-in-out text-code-foreground text-sm font-medium cursor-pointer"
						onClick={handleTakeATour}
						type="button">
						Take a Tour
						<span className="codicon codicon-play scale-90"></span>
					</button>
				</div>
			)}
		</div>
	)
}

export default HomeHeader
