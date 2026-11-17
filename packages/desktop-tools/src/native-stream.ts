import {nativeMediaLaunch} from './native-helper';
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import type { HostToolsLaunch } from "./host-bridge";

import {
  videoPacket,
  type VideoConfig,
  type VideoPacket,
} from "./video-protocol";
export {
  videoPacket,
  type VideoConfig,
  type VideoPacket,
  type VideoFrame,
} from "./video-protocol";

/** One owned encoder process. Hosts authorize start, current viewers and stop. */
export class NativeScreenStream {
  private child: ChildProcessWithoutNullStreams | null = null;
  private buffer = "";
  private sequence = 0;
  private configured = false;
  private finish: ((error?: Error) => void) | null = null;
  constructor(
    private readonly launch: Pick<
      HostToolsLaunch,
      "command" | "args" | "env" | "cwd"
    >,
  ) { this.launch=nativeMediaLaunch(this.launch); }
  async start(
    options: {
      display_id?: number;
      fps?: number;
      max_duration_seconds?: number;
    },
    onPacket: (packet: VideoPacket) => void,
    onEnd: (error?: Error) => void,
  ): Promise<VideoConfig> {
    if (this.child) throw new Error("video_already_started");
    if (
      options.display_id !== undefined &&
      (!Number.isSafeInteger(options.display_id) ||
        options.display_id < 0 ||
        options.display_id > 0xffffffff)
    )
      throw new Error("invalid_video_display");
    const fps = options.fps ?? 20,
      seconds = options.max_duration_seconds ?? 60;
    if (
      !Number.isSafeInteger(fps) ||
      fps < 1 ||
      fps > 30 ||
      !Number.isSafeInteger(seconds) ||
      seconds < 1 ||
      seconds > 300
    )
      throw new Error("invalid_video_options");
    const child = spawn(
      this.launch.command,
      [...this.launch.args, "--desktop-stream"],
      {
        stdio: ["pipe", "pipe", "pipe"],
        shell: false,
        windowsHide: true,
        cwd: this.launch.cwd,
        env: { ...process.env, ...this.launch.env },
      },
    );
    this.child = child;
    this.sequence = 0;
    this.configured = false;
    this.buffer = "";
    child.stderr.resume();
    child.stdout.setEncoding("utf8");
    return new Promise((resolve, reject) => {
      let settled = false,
        ended = false;
      const timeout = setTimeout(
        () => end(new Error("video_start_timeout")),
        15000,
      );
      const end = (error?: Error) => {
        if (ended) return;
        ended = true;
        clearTimeout(timeout);
        if (!settled) {
          settled = true;
          reject(error ?? new Error("video_closed_before_ready"));
        }
        if (this.child === child) {
          this.child = null;
          child.kill();
        }
        this.finish = null;
        onEnd(error);
      };
      this.finish = end;
      child.stdout.on("data", (chunk: string) => {
        if (this.child !== child) return;
        this.buffer += chunk;
        if (Buffer.byteLength(this.buffer) > 2 * 1024 * 1024) {
          end(new Error("video_packet_limit"));
          return;
        }
        for (;;) {
          const i = this.buffer.indexOf("\n");
          if (i < 0) break;
          const line = this.buffer.slice(0, i);
          this.buffer = this.buffer.slice(i + 1);
          try {
            const packet = videoPacket(JSON.parse(line));
            if (packet.type === "config") {
              if (this.configured) throw new Error("duplicate_video_config");
              this.configured = true;
              settled = true;
              clearTimeout(timeout);
              resolve(packet);
            } else {
              if (
                !this.configured ||
                packet.seq !== this.sequence++ ||
                (packet.seq === 0 && !packet.key)
              )
                throw new Error("video_sequence");
            }
            onPacket(packet);
          } catch (e) {
            end(e instanceof Error ? e : new Error("invalid_video_packet"));
            return;
          }
        }
      });
      child.on("error", (error) => end(error));
      child.on("close", (code) =>
        end(code ? new Error("video_encoder_failed") : undefined),
      );
      child.stdin.on("error", (error) => end(error));
      child.stdin.write(
        JSON.stringify({ ...options, fps, max_duration_seconds: seconds }) +
          "\n",
      );
    });
  }
  stop(): void {
    const child = this.child;
    if (!child) return;
    this.finish?.();
    child.stdin.end('{"type":"stop"}\n');
    const kill = setTimeout(() => {
      if (child.exitCode === null && child.signalCode === null)
        child.kill("SIGKILL");
    }, 500);
    kill.unref();
  }
}
