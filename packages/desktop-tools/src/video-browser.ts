import { videoPacket, type VideoConfig } from "./video-protocol";
export {
  videoPacket,
  type VideoConfig,
  type VideoPacket,
  type VideoFrame,
} from "./video-protocol";

/** Bounded Annex-B decoder shared by optional desktop viewers and publishers. */
export class VideoCanvasDecoder {
  private decoder: any;
  private sequence = 0;
  private closed = false;
  constructor(
    private readonly canvas: () => HTMLCanvasElement | null,
    private readonly onConfig: (config: VideoConfig) => void,
    private readonly onError: (message: string) => void,
    private readonly onFrame?: () => void,
  ) {}
  async accept(value: unknown): Promise<void> {
    if (this.closed) return;
    const packet = videoPacket(value),
      Codec = (globalThis as any).VideoDecoder,
      Chunk = (globalThis as any).EncodedVideoChunk;
    if (!Codec || !Chunk)
      throw new Error("Live video decoding unavailable in this client");
    if (packet.type === "config") {
      if (this.decoder && this.decoder.state !== "closed") this.decoder.close();
      this.sequence = 0;
      const config = {
        codec: packet.codec,
        codedWidth: packet.width,
        codedHeight: packet.height,
        optimizeForLatency: true,
      };
      const support = await Codec.isConfigSupported(config);
      if (!support.supported) throw new Error("Video codec unavailable");
      if (this.closed) return;
      this.onConfig(packet);
      this.decoder = new Codec({
        output: (frame: any) => {
          try {
            if (this.closed) return;
            if (
              frame.displayWidth !== packet.width ||
              frame.displayHeight !== packet.height
            ) {
              this.onError("Desktop dimensions changed; reopen the view");
              return;
            }
            const canvas = this.canvas();
            if (canvas) {
              canvas.width = frame.displayWidth;
              canvas.height = frame.displayHeight;
              canvas.getContext("2d")?.drawImage(frame, 0, 0);
              this.onFrame?.();
            }
          } finally {
            frame.close();
          }
        },
        error: () => this.onError("Video decoder unavailable"),
      });
      this.decoder.configure(config);
    } else {
      if (
        !this.decoder ||
        packet.seq !== this.sequence++ ||
        (packet.seq === 0 && !packet.key)
      )
        throw new Error("Video stream interrupted");
      if (this.decoder.decodeQueueSize > 16)
        throw new Error("Video decoder is too slow");
      const data = Uint8Array.from(atob(packet.data), (c) => c.charCodeAt(0));
      this.decoder.decode(
        new Chunk({
          type: packet.key ? "key" : "delta",
          timestamp: packet.timestamp_us,
          data,
        }),
      );
    }
  }
  close(): void {
    this.closed = true;
    if (this.decoder && this.decoder.state !== "closed") this.decoder.close();
  }
}
