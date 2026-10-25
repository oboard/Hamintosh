export interface ProbeResult {
  mode: string;
  status: string;
  detail: string;
  value: number;
  errno: number;
  signal: number;
  traps: number;
  faultPc: string;
  faultAddress: string;
  syscall: string;
  selfRebaseWitness: boolean;
  requestPath: string;
  message: string;
  unsupportedCalls: string;
}

export interface DiagnosticsResult {
  runtime: string;
  rawProbe: ProbeResult;
  machoProbe: ProbeResult;
  packagedProbe: ProbeResult;
  targetImage: ProbeResult;
  darwinProbe: ProbeResult;
  pacProbe: ProbeResult;
  bootStackProbe: ProbeResult;
  rebaseProbe: ProbeResult;
  dyldBootstrap: ProbeResult;
  compatReport: string;
}

export const runDiagnostics: (probeDirectory: string, executablePath: string,
  sysrootPath: string) => Promise<DiagnosticsResult>;
