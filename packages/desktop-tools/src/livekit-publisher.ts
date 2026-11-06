import { Room, Track } from "livekit-client";
import { VideoCanvasDecoder } from "./video-browser";
import type { VideoGrant } from "./electron-video";
export type PublisherBridge = {
  leases(): Promise<VideoGrant[]>;
  start(id: string): Promise<void>;
  ready(id: string, ok: boolean): Promise<void>;
  onPacket(cb: (id: string, packet: unknown) => void): () => void;
  onEnded(cb: (id: string) => void): () => void;
};
export function startLiveKitPublisher(bridge: PublisherBridge): () => void {
  const streams = new Map<
    string,
    {
      room: Room;
      canvas: HTMLCanvasElement;
      decoder: VideoCanvasDecoder;
      alive: boolean;
      tail: Promise<void>;
      queued: number;
      track: MediaStreamTrack | null;
    }
  >();
  const stop = (id: string) => {
    const state = streams.get(id);
    if (!state) return;
    state.alive = false;
    state.decoder.close();
    state.track?.stop();
    void state.room.disconnect();
    streams.delete(id);
  };
  const packet = bridge.onPacket((id, packet) => {
    const state = streams.get(id);
    if (!state || !state.alive) return;
    if (++state.queued > 16) {
      void bridge.ready(id, false);
      stop(id);
      return;
    }
    state.tail = state.tail
      .then(() => state.decoder.accept(packet))
      .catch(() => {
        void bridge.ready(id, false);
        stop(id);
      })
      .finally(() => {
        state.queued--;
      });
  });
  const ended = bridge.onEnded(stop);
  const publish = async (grant: VideoGrant) => {
    const room = new Room(),
      canvas = document.createElement("canvas");
    let first: () => void = () => {};
    const ready = new Promise<void>((resolve) => {
      first = resolve;
    });
    const state = {
      room,
      canvas,
      alive: true,
      decoder: null as unknown as VideoCanvasDecoder,
      tail: Promise.resolve(),
      queued: 0,
      track: null as MediaStreamTrack | null,
    };
    state.decoder = new VideoCanvasDecoder(
      () => canvas,
      (config) => {
        canvas.width = config.width;
        canvas.height = config.height;
      },
      () => {
        void bridge.ready(grant.id, false);
        stop(grant.id);
      },
      () => first(),
    );
    streams.set(grant.id, state);
    try {
      await bridge.start(grant.id);
      let deadline: ReturnType<typeof setTimeout> | undefined;
      try {
        await Promise.race([
          ready,
          new Promise((_, reject) => {
            deadline = setTimeout(
              () => reject(new Error("first_frame_timeout")),
              15000,
            );
          }),
        ]);
      } finally {
        clearTimeout(deadline);
      }
      if (!state.alive) return;
      await room.connect(grant.url, grant.token, { autoSubscribe: false });
      if (!state.alive) {
        await room.disconnect();
        return;
      }
      const track = canvas.captureStream(20).getVideoTracks()[0];
      if (!track) throw new Error("screen_track_unavailable");
      state.track = track;
      await room.localParticipant.publishTrack(track, {
        source: Track.Source.ScreenShare,
        videoEncoding: { maxBitrate: 3000000, maxFramerate: 20 },
      });
      await bridge.ready(grant.id, true);
    } catch {
      await bridge.ready(grant.id, false).catch(() => {});
      stop(grant.id);
    }
  };
  let syncing = false;
  const timer = setInterval(() => {
    if (syncing) return;
    syncing = true;
    void bridge
      .leases()
      .then((leases) => {
        const wanted = new Set(leases.map((lease) => lease.id));
        for (const id of streams.keys()) if (!wanted.has(id)) stop(id);
        for (const lease of leases)
          if (!streams.has(lease.id)) void publish(lease);
      })
      .catch(() => {
        for (const id of [...streams.keys()]) stop(id);
      })
      .finally(() => {
        syncing = false;
      });
  }, 500);
  return () => {
    clearInterval(timer);
    packet();
    ended();
    for (const id of streams.keys()) stop(id);
  };
}
