const NativeMock: Record<string, Object> = {
  'runDiagnostics': () => {
    return Promise.reject(new Error('请在 ARM64 真机上运行原生执行探针，预览器不支持此检查。'));
  },
};

export default NativeMock;
