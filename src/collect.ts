import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import readline from "node:readline";
import { bold, cyan, dim, green, yellow } from "./colors.ts";
import { Redactor } from "./redactor.ts";
import { runReview } from "./review.ts";
import { computeSecretHash } from "./secrets.ts";
import { formatTruffleHogFinding, saveTruffleHogReport, scanFilesWithTruffleHog, trufflehogReportPath } from "./trufflehog.ts";
import type { CollectOptions, InitOptions, JsonObject, ReviewOptions } from "./types.ts";
import { LOCAL_MANIFEST_FILE, REDACTION_VERSION, REMOTE_MANIFEST_CACHE_FILE } from "./types.ts";
import {
  cwdToSessionDirName,
  downloadRemoteManifest,
  ensureWorkspaceDirs,
  loadLocalManifest,
  readWorkspaceConfig,
  resetWorkspaceForCollect,
  sha256File,
  workspacePath,
  writeJsonlFile,
  writeWorkspaceConfig,
} from "./workspace.ts";

const TRUFFLEHOG_BATCH_SIZE = 50;

export async function runInit(options: InitOptions): Promise<void> {
  resetWorkspaceForCollect(options.workspace);
  ensureWorkspaceDirs(options.workspace);
  writeWorkspaceConfig(options.workspace, {
    cwd: options.cwd,
    repo: options.repo,
    noImages: options.noImages,
    keepSignatures: options.keepSignatures,
  });
  console.log(`${bold("Initialized workspace:")} ${options.workspace}`);
  console.log(`${bold("CWD:")} ${options.cwd}`);
  console.log(`${bold("Repo:")} ${options.repo}`);
  console.log(`${bold("Images:")} ${options.noImages ? "stripped" : "preserved"}`);
  console.log(`${bold("Signatures:")} ${options.keepSignatures ? "preserved" : "stripped"}`);
}

export async function runCollect(options: CollectOptions): Promise<void> {
  resetWorkspaceForCollect(options.workspace);
  ensureWorkspaceDirs(options.workspace);

  const config = readWorkspaceConfig(options.workspace);

  const remoteManifestCachePath = workspacePath(options.workspace, REMOTE_MANIFEST_CACHE_FILE);
  const remoteManifest = await downloadRemoteManifest(config.repo, remoteManifestCachePath);
  const sessionDir = findSessionDir(config.cwd);
  let sessionFiles = fs.readdirSync(sessionDir).filter((file) => file.endsWith(".jsonl")).sort();
  if (options.session) {
    sessionFiles = sessionFiles.filter((file) => file.includes(options.session!));
  }
  const redactor = new Redactor(options.envFile, options.secrets, !!config.noImages, !!config.keepSignatures);
  const secretsHash = computeSecretHash(options.envFile, options.secrets);
  const localManifestPath = workspacePath(options.workspace, LOCAL_MANIFEST_FILE);
  const localManifest = loadLocalManifest(localManifestPath);

  let reusedLocal = 0;
  let skippedRemote = 0;
  let processed = 0;
  let processedNew = 0;
  let processedChanged = 0;
  let sessionsWithSecretRedactions = 0;
  let sessionsWithTruffleHogFindings = 0;
  let sessionsWithVerifiedTruffleHogFindings = 0;
  let sessionsWithUnverifiedTruffleHogFindings = 0;
  let sessionsWithUnknownTruffleHogFindings = 0;
  const processedTruffleHogFindings: Array<{ file: string; findings: string[] }> = [];
  const trufflehogScanQueue: Array<{ file: string; redactedPath: string; redactedHash: string }> = [];

  console.log(bold("Collect"));
  process.stdout.write(`  ${bold("Sessions found:")} 0`);

  for (let index = 0; index < sessionFiles.length; index++) {
    const file = sessionFiles[index];
    process.stdout.write(`\r  ${bold("Sessions found:")} ${index + 1}`);

    const inputPath = path.join(sessionDir, file);
    const sourceHash = await sha256File(inputPath);
    const redactionKey = createRedactionKey(sourceHash, secretsHash, !!config.noImages, !!config.keepSignatures);
    const remoteEntry = remoteManifest.get(file);
    const localEntry = localManifest.get(file);
    const redactedPath = workspacePath(options.workspace, "redacted", file);
    const reportPath = workspacePath(options.workspace, "reports", `${file}.report.jsonl`);
    const trufflehogPath = trufflehogReportPath(options.workspace, file);

    if (
      !options.force
      && localEntry
      && localEntry.redaction_key === redactionKey
      && fs.existsSync(redactedPath)
      && fs.existsSync(reportPath)
      && fs.existsSync(trufflehogPath)
    ) {
      reusedLocal++;
      continue;
    }

    if (!options.force && remoteEntry?.redaction_key === redactionKey) {
      skippedRemote++;
      continue;
    }

    fs.rmSync(workspacePath(options.workspace, "review", `${file}.review.json`), { force: true });
    fs.rmSync(workspacePath(options.workspace, "review-chunks", file), { recursive: true, force: true });

    const result = await processSessionFile(inputPath, redactedPath, reportPath, redactor);

    if (!localEntry && !remoteEntry) processedNew++;
    else processedChanged++;
    if (result.hasSecretRedactions) {
      sessionsWithSecretRedactions++;
    }

    trufflehogScanQueue.push({
      file,
      redactedPath,
      redactedHash: result.redactedHash,
    });

    localManifest.set(file, {
      file,
      source_file: inputPath,
      source_hash: sourceHash,
      redaction_key: redactionKey,
      redacted_hash: result.redactedHash,
      entry_count: result.entryCount,
      findings: result.findings,
      lines_with_findings: result.linesWithFindings,
    });
    processed++;
  }

  if (trufflehogScanQueue.length > 0) {
    console.log();
    console.log();
    console.log(bold("TruffleHog"));
    process.stdout.write(`  ${bold("Processed sessions:")} 0/${trufflehogScanQueue.length}`);
  }

  let trufflehogProcessed = 0;
  for (let i = 0; i < trufflehogScanQueue.length; i += TRUFFLEHOG_BATCH_SIZE) {
    const batch = trufflehogScanQueue.slice(i, i + TRUFFLEHOG_BATCH_SIZE);
    const reports = await scanFilesWithTruffleHog(batch);

    for (const entry of batch) {
      const trufflehogReport = reports.get(entry.file);
      if (!trufflehogReport) {
        throw new Error(`Missing TruffleHog report for ${entry.file}`);
      }
      saveTruffleHogReport(trufflehogReportPath(options.workspace, entry.file), trufflehogReport);

      if (trufflehogReport.summary.findings > 0) {
        sessionsWithTruffleHogFindings++;
        processedTruffleHogFindings.push({
          file: entry.file,
          findings: trufflehogReport.findings.map((finding) => formatTruffleHogFinding(finding)),
        });
      }
      if (trufflehogReport.summary.verified > 0) {
        sessionsWithVerifiedTruffleHogFindings++;
      }
      if (trufflehogReport.summary.unverified > 0) {
        sessionsWithUnverifiedTruffleHogFindings++;
      }
      if (trufflehogReport.summary.unknown > 0) {
        sessionsWithUnknownTruffleHogFindings++;
      }

      trufflehogProcessed++;
      process.stdout.write(`\r  ${bold("Processed sessions:")} ${trufflehogProcessed}/${trufflehogScanQueue.length}`);
    }
  }

  if (trufflehogScanQueue.length > 0) {
    console.log();
  }

  const keptEntries = [...localManifest.values()]
    .filter((entry) => fs.existsSync(workspacePath(options.workspace, "redacted", entry.file))
      && fs.existsSync(workspacePath(options.workspace, "reports", `${entry.file}.report.jsonl`))
      && fs.existsSync(trufflehogReportPath(options.workspace, entry.file)))
    .sort((a, b) => a.file.localeCompare(b.file));
  writeJsonlFile(localManifestPath, keptEntries);

  console.log();
  console.log();
  console.log(bold("Redaction"));
  console.log(`  ${bold("Processed sessions:")} ${green(String(processed))}`);
  console.log(`  ${bold("New sessions:")} ${processedNew}`);
  console.log(`  ${bold("Changed sessions:")} ${processedChanged}`);
  console.log(`  ${bold("Sessions with secret redactions:")} ${sessionsWithSecretRedactions}`);
  console.log(`  ${bold("Sessions with any TruffleHog findings:")} ${sessionsWithTruffleHogFindings}`);
  console.log(`  ${bold("Sessions with verified TruffleHog findings:")} ${sessionsWithVerifiedTruffleHogFindings}`);
  console.log(`  ${bold("Sessions with unverified TruffleHog findings:")} ${sessionsWithUnverifiedTruffleHogFindings}`);
  console.log(`  ${bold("Sessions with unknown TruffleHog findings:")} ${sessionsWithUnknownTruffleHogFindings}`);

  if (processedTruffleHogFindings.length > 0) {
    console.log();
    console.log(bold("TruffleHog findings"));
    for (const entry of processedTruffleHogFindings) {
      console.log(`  ${yellow(entry.file)}`);
      for (const finding of entry.findings.slice(0, 10)) {
        console.log(`    ${finding}`);
      }
      if (entry.findings.length > 10) {
        console.log(`    ${dim(`... ${entry.findings.length - 10} more`)}`);
      }
    }
  }

  const reviewOptions: ReviewOptions = {
    workspace: options.workspace,
    contextFiles: options.contextFiles,
    provider: options.provider,
    model: options.model,
    thinking: options.thinking,
    parallel: options.parallel,
    denyPatterns: options.denyPatterns,
    session: options.session,
  };
  await runReview(reviewOptions);
}

function createRedactionKey(sourceHash: string, secretsHash: string, noImages: boolean, keepSignatures: boolean): string {
  return `v${REDACTION_VERSION}:${sourceHash}:${secretsHash}:${noImages ? "no-images" : "keep-images"}:${keepSignatures ? "keep-signatures" : "strip-signatures"}`;
}

function findSessionDir(cwd: string): string {
  const sessionsBase = path.join(os.homedir(), ".pi", "agent", "sessions");
  const dir = path.join(sessionsBase, cwdToSessionDirName(cwd));
  if (!fs.existsSync(dir)) {
    throw new Error(`Session directory not found for cwd: ${cwd}`);
  }
  return dir;
}

async function processSessionFile(
  inputPath: string,
  redactedPath: string,
  reportPath: string,
  redactor: Redactor,
): Promise<{ redactedHash: string; entryCount: number; findings: number; linesWithFindings: number; hasSecretRedactions: boolean }> {
  const input = fs.createReadStream(inputPath, { encoding: "utf-8" });
  const reader = readline.createInterface({ input, crlfDelay: Infinity });
  const redactedStream = fs.createWriteStream(redactedPath, { encoding: "utf-8" });
  const reportStream = fs.createWriteStream(reportPath, { encoding: "utf-8" });
  const redactedHash = createHash("sha256");

  let lineNumber = 0;
  let entryCount = 0;
  let findingsCount = 0;
  let linesWithFindings = 0;
  let hasSecretRedactions = false;

  for await (const line of reader) {
    lineNumber++;
    if (line.trim() === "") continue;

    try {
      const parsed = JSON.parse(line) as unknown;
      if (!isRecord(parsed)) {
        throw new Error("Expected a JSON object");
      }
      const event = parsed as JsonObject;
      const result = await redactor.redactEvent(event);
      const serialized = `${JSON.stringify(result.redacted)}\n`;
      await writeToStream(redactedStream, serialized);
      redactedHash.update(serialized);
      entryCount++;

      if (result.findings.length > 0) {
        linesWithFindings++;
        findingsCount += result.findings.length;
        if (result.findings.some((f) => f.detector === "literal-secret")) {
          hasSecretRedactions = true;
        }
        appendReportLine(reportStream, {
          line_number: lineNumber,
          entry_type: typeof event.type === "string" ? event.type : undefined,
          entry_id: typeof event.id === "string" ? event.id : undefined,
          findings: result.findings,
        });
      }
    } catch (error) {
      appendReportLine(reportStream, {
        line_number: lineNumber,
        findings: [
          {
            detector: "parse-error",
            severity: "high",
            jsonPath: "$",
            replacement: "",
            count: 1,
            detail: error instanceof Error ? error.message : String(error),
          },
        ],
      });
      linesWithFindings++;
      findingsCount++;
    }
  }

  await closeStream(redactedStream);
  await closeStream(reportStream);

  return {
    redactedHash: `sha256:${redactedHash.digest("hex")}`,
    entryCount,
    findings: findingsCount,
    linesWithFindings,
    hasSecretRedactions,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function appendReportLine(stream: fs.WriteStream, value: unknown): void {
  stream.write(`${JSON.stringify(value)}\n`);
}

function writeToStream(stream: fs.WriteStream, data: string): Promise<void> {
  return new Promise((resolve, reject) => {
    stream.write(data, (error) => {
      if (error) reject(error);
      else resolve();
    });
  });
}

function closeStream(stream: fs.WriteStream): Promise<void> {
  return new Promise((resolve, reject) => {
    stream.end((error?: Error | null) => {
      if (error) reject(error);
      else resolve();
    });
  });
}

