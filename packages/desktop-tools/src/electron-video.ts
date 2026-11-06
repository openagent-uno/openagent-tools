import { BrowserWindow, ipcMain, type IpcMainInvokeEvent } from "electron";
import { NativeScreenStream } from "./native-stream";
import type { HostToolsLaunch } from "./host-bridge";
export type VideoGrant = {
  id: string;
  monitorId: string;
  url: string;
  token: string;
  actorUserId: string;
};
export interface VideoHostOptions {
  url: string;
  preload: string;
  launch: Pick<HostToolsLaunch, "command" | "args" | "env" | "cwd">;
}

/** Optional UI transport. Only the authenticated host may supply or renew grants. */
export class ComputerVideoHost {
  private window: BrowserWindow | null = null;
  private leases = new Map<string, { grant: VideoGrant; expires: number }>();
  private pending = new Map<
    string,
    { resolve(): void; reject(error: Error): void }
  >();
  private streams = new Map<string, NativeScreenStream>();
  private timer: ReturnType<typeof setInterval>;
  constructor(private readonly options: VideoHostOptions) {
    const trusted = (event: IpcMainInvokeEvent) => {
      if (
        !this.window ||
        event.sender !== this.window.webContents ||
        event.senderFrame !== event.sender.mainFrame ||
        event.senderFrame?.url !== options.url
      )
        throw new Error("untrusted_computer_video_sender");
    };
    ipcMain.handle("computer-video:leases", (event) => {
      trusted(event);
      return [...this.leases.values()].map((value) => value.grant);
    });
    ipcMain.handle("computer-video:start", async (event, id: unknown) => {
      trusted(event);
      if (typeof id !== "string") throw new Error("invalid_video_lease");
      const lease = this.leases.get(id);
      if (!lease || lease.expires <= Date.now() || this.streams.has(id))
        throw new Error("invalid_video_lease");
      await this.openEncoder(id);
    });
    ipcMain.handle(
      "computer-video:ready",
      (event, id: unknown, ok: unknown) => {
        trusted(event);
        if (typeof id !== "string" || !this.leases.has(id))
          throw new Error("invalid_video_lease");
        if (ok === true) this.pending.get(id)?.resolve();
        else {
          this.pending
            .get(id)
            ?.reject(new Error("screen_capture_or_video_unavailable"));
          this.stop(id);
        }
      },
    );
    this.timer = setInterval(() => {
      for (const [id, lease] of this.leases)
        if (lease.expires <= Date.now()) this.stop(id);
    }, 1000);
  }
  private async openEncoder(id: string): Promise<void> {
    const lease = this.leases.get(id);
    if (!lease || lease.expires <= Date.now()) return;
    const display = Number(lease.grant.monitorId);
    if (!Number.isSafeInteger(display) || display < 0 || display > 0xffffffff)
      throw new Error("invalid_video_display");
    const stream = new NativeScreenStream(this.options.launch);
    this.streams.set(id, stream);
    await stream.start(
      { display_id: display, fps: 20, max_duration_seconds: 300 },
      (packet) => {
        const current = this.leases.get(id);
        if (this.window && current === lease && current.expires > Date.now())
          this.window.webContents.send("computer-video:packet", id, packet);
        else this.stop(id);
      },
      (error) => {
        if (this.streams.get(id) !== stream) return;
        this.streams.delete(id);
        if (!this.leases.has(id)) return;
        if (
          !error &&
          this.leases.get(id) === lease &&
          lease.expires > Date.now()
        ) {
          void this.openEncoder(id).catch(() => {
            this.window?.webContents.send("computer-video:ended", id);
            this.stop(id);
          });
          return;
        }
        this.window?.webContents.send("computer-video:ended", id);
        if (error) this.pending.get(id)?.reject(error);
        this.stop(id);
      },
    );
  }
  async start(grant: VideoGrant): Promise<void> {
    const endpoint = new URL(grant.url);
    if (
      endpoint.username ||
      endpoint.password ||
      endpoint.hash ||
      endpoint.search ||
      !["ws:", "wss:"].includes(endpoint.protocol) ||
      (endpoint.protocol === "ws:" &&
        !["localhost", "127.0.0.1", "[::1]"].includes(endpoint.hostname) &&
        !endpoint.hostname.endsWith(".localhost"))
    )
      throw new Error("invalid_video_endpoint");
    if (this.leases.size >= 8 && !this.leases.has(grant.id))
      throw new Error("computer_video_capacity");
    this.leases.set(grant.id, { grant, expires: Date.now() + 20000 });
    let timer: ReturnType<typeof setTimeout>;
    const ready = new Promise<void>((resolve, reject) => {
      this.pending.set(grant.id, { resolve, reject });
      timer = setTimeout(
        () => reject(new Error("screen_share_start_timeout")),
        19000,
      );
    });
    const completed = ready.finally(() => {
      clearTimeout(timer);
      this.pending.delete(grant.id);
    });
    void completed.catch(() => {});
    try {
      if (!this.window) {
        const window = new BrowserWindow({
          show: false,
          webPreferences: {
            preload: this.options.preload,
            contextIsolation: true,
            sandbox: true,
            nodeIntegration: false,
            backgroundThrottling: false,
            partition: "computer-video",
          },
        });
        this.window = window;
        window.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
        window.webContents.on("will-navigate", (event) =>
          event.preventDefault(),
        );
        window.webContents.session.setPermissionRequestHandler(
          (_contents, _permission, callback) => callback(false),
        );
        window.webContents.session.setPermissionCheckHandler(() => false);
        window.webContents.session.webRequest.onBeforeRequest(
          (details, callback) => {
            const url = new URL(details.url),
              local = new URL(this.options.url);
            const allowed =
              (url.protocol === "file:" &&
                url.pathname.startsWith(
                  local.pathname.replace(/[^/]+$/, ""),
                )) ||
              [...this.leases.values()].some((value) => {
                const endpoint = new URL(value.grant.url);
                return (
                  url.host === endpoint.host &&
                  [
                    endpoint.protocol,
                    endpoint.protocol === "wss:" ? "https:" : "http:",
                  ].includes(url.protocol)
                );
              });
            callback({ cancel: !allowed });
          },
        );
        window.on("closed", () => {
          if (this.window === window) {
            this.window = null;
            for (const stream of this.streams.values()) stream.stop();
            this.streams.clear();
            this.leases.clear();
          }
        });
        await window.loadURL(this.options.url);
      }
      await completed;
    } catch (error) {
      this.stop(grant.id);
      throw error;
    }
  }
  renew(id: string): void {
    const lease = this.leases.get(id);
    if (lease) lease.expires = Date.now() + 20000;
  }
  stop(id: string): void {
    this.pending.get(id)?.reject(new Error("video_stopped"));
    this.pending.delete(id);
    this.leases.delete(id);
    const stream = this.streams.get(id);
    this.streams.delete(id);
    stream?.stop();
    if (!this.leases.size) {
      this.window?.destroy();
      this.window = null;
    }
  }
  stopAll(): void {
    for (const id of [...this.leases.keys()]) this.stop(id);
  }
  dispose(): void {
    clearInterval(this.timer);
    this.stopAll();
    for (const channel of ["leases", "start", "ready"])
      ipcMain.removeHandler("computer-video:" + channel);
  }
}
