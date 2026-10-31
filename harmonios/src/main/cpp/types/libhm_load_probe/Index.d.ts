export const probeRuntimeLoad: () => string;

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

export interface RuntimeExports {
  runDiagnostics: (directory: string, executable: string, sysroot: string) => Promise<DiagnosticsResult>;
  attachRenderSurface: (id: string, width: number, height: number) => RenderSurfaceResult;
  detachRenderSurface: () => RenderSurfaceResult;
  setGuestSafeArea: (top: number, left: number, bottom: number, right: number) => void;
  dispatchTouchEvent: (type: number, x: number, y: number) => boolean;
  cancelDiagnostics: () => void;
  vulkanPreflight: () => string;
  metalRenderProbe: () => string;
  caRendererProbe: () => string;
  getFrameDiagnostics: () => string;
  resetFrameDiagnostics: () => string;
}
export const loadRuntime: (cacheLibraryName: string) => RuntimeExports;
