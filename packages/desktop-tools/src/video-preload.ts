import { contextBridge, ipcRenderer } from "electron";
contextBridge.exposeInMainWorld(
  "computerVideo",
  Object.freeze({
    leases: () => ipcRenderer.invoke("computer-video:leases"),
    start: (id: string) => ipcRenderer.invoke("computer-video:start", id),
    ready: (id: string, ok: boolean) =>
      ipcRenderer.invoke("computer-video:ready", id, ok),
    onPacket: (callback: (id: string, packet: unknown) => void) => {
      const listener = (_event: unknown, id: string, packet: unknown) =>
        callback(id, packet);
      ipcRenderer.on("computer-video:packet", listener);
      return () =>
        ipcRenderer.removeListener("computer-video:packet", listener);
    },
    onEnded: (callback: (id: string) => void) => {
      const listener = (_event: unknown, id: string) => callback(id);
      ipcRenderer.on("computer-video:ended", listener);
      return () => ipcRenderer.removeListener("computer-video:ended", listener);
    },
  }),
);
