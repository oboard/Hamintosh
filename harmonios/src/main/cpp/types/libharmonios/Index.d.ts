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
  dyldEntered: boolean;
  appExecuted: boolean;
  requestPath: string;
  message: string;
  unsupportedCalls: string;
}

export interface RuntimeVerificationResult {
  runtimeExecutionAttempted: boolean;
  dyldEntered: boolean;
  runtimeExecutionVerified: boolean;
  appExecuted: boolean;
  targetImageStatus: string;
  runtimeStatus: string;
  traps: number;
  signal: number;
  faultPc: string;
  faultAddress: string;
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
  runtimeVerification: RuntimeVerificationResult;
  compatReport: string;
  caRendererProbe: string;
  frameDiagnostics: string;
}

export interface RenderSurfaceResult {
  success: boolean;
  attached: boolean;
  status: string;
}

export const runDiagnostics: (probeDirectory: string, executablePath: string,
  sysrootPath: string) => Promise<DiagnosticsResult>;
export const attachRenderSurface: (surfaceId: string, width: number,
  height: number) => RenderSurfaceResult;
export const detachRenderSurface: () => RenderSurfaceResult;
export const getRenderSurfaceStatus: () => RenderSurfaceResult;
export const presentTestPattern: (patternId?: number) => RenderSurfaceResult;
export const getFrameDiagnostics: () => string;
export const resetFrameDiagnostics: () => string;
export const dispatchTouchEvent: (type: number, x: number, y: number) => boolean;
export const setGuestSafeArea: (top: number, left: number, bottom: number, right: number) => void;
export const cancelDiagnostics: () => void;
export const vulkanPreflight: () => string;
export const metalRenderProbe: () => string;
export const caRendererProbe: () => string;
