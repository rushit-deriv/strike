import * as fs from "fs/promises"
import * as path from "path"
import * as vscode from "vscode"

async function pathExists(p: string): Promise<boolean> {
	try {
		await fs.access(p)
		return true
	} catch {
		return false
	}
}

async function copyDir(src: string, dest: string): Promise<void> {
	await fs.mkdir(dest, { recursive: true })
	const entries = await fs.readdir(src, { withFileTypes: true })
	for (const entry of entries) {
		const srcPath = path.join(src, entry.name)
		const destPath = path.join(dest, entry.name)
		if (entry.isDirectory()) {
			await copyDir(srcPath, destPath)
		} else if (entry.isFile()) {
			await fs.copyFile(srcPath, destPath)
		}
	}
}

async function indexMarkdown(dir: string): Promise<Record<string, unknown>> {
	const items: Array<{ title: string; slug: string; relPath: string }> = []
	async function walk(d: string) {
		const ents = await fs.readdir(d, { withFileTypes: true })
		for (const e of ents) {
			const full = path.join(d, e.name)
			if (e.isDirectory()) {
				await walk(full)
			} else if (e.isFile() && e.name.toLowerCase().endsWith(".md")) {
				const content = await fs.readFile(full, "utf8")
				const m = content.match(/^#\s+(.+)$/m)
				const title = m ? m[1].trim() : path.parse(e.name).name
				const slug = title
					.toLowerCase()
					.replace(/[^a-z0-9]+/g, "-")
					.replace(/(^-|-$)/g, "")
				items.push({ title, slug, relPath: path.relative(dir, full) })
			}
		}
	}
	await walk(dir)
	return { generatedAt: new Date().toISOString(), count: items.length, items }
}

export async function installBundledKnowledgeBase(context: vscode.ExtensionContext): Promise<void> {
	const wsFolder = vscode.workspace.workspaceFolders?.[0]
	if (!wsFolder) return
	const workspaceRoot = wsFolder.uri.fsPath

	const kbSrc = context.asAbsolutePath(path.join("assets", "kb"))
	const kbDest = path.join(workspaceRoot, "docs", "pentest", "kb")

	// Skip if source does not exist (no KB bundled)
	if (!(await pathExists(kbSrc))) return

	const installKey = `strike.kbInstalled:${kbDest}`
	const alreadyInstalled = context.globalState.get<boolean>(installKey)
	if (alreadyInstalled) return

	const choice = await vscode.window.showInformationMessage(
		"Strike: Install bundled knowledge base into this workspace?",
		{ detail: `This will copy docs into ${kbDest}` },
		"Install",
		"Skip",
	)

	if (choice !== "Install") {
		await context.globalState.update(installKey, true) // Don't prompt again for this workspace
		return
	}

	try {
		await copyDir(kbSrc, kbDest)
		const index = await indexMarkdown(kbDest)
		await fs.writeFile(path.join(kbDest, "index.json"), JSON.stringify(index, null, 2), "utf8")
		await context.globalState.update(installKey, true)
		void vscode.window.showInformationMessage("Strike: Knowledge base installed.")
	} catch (err: any) {
		void vscode.window.showErrorMessage(`Strike KB install failed: ${err?.message ?? String(err)}`)
	}
}
