export type VideoConfig = {
  type: "config";
  protocol: "openagent-video/1";
  codec: string;
  width: number;
  height: number;
  input_width: number;
  input_height: number;
  fps: number;
};
export type VideoFrame = {
  type: "frame";
  seq: number;
  timestamp_us: number;
  key: boolean;
  data: string;
};
export type VideoPacket = VideoConfig | VideoFrame;
export function videoPacket(value: unknown): VideoPacket {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error("invalid_video_packet");
  const v = value as Record<string, unknown>;
  if (v.type === "config") {
    if (
      v.protocol !== "openagent-video/1" ||
      typeof v.codec !== "string" ||
      !/^avc1\.[a-fA-F0-9]{6}$/.test(v.codec) ||
      !["width", "height", "input_width", "input_height"].every(
        (k) =>
          Number.isSafeInteger(v[k]) &&
          (v[k] as number) >= 2 &&
          (v[k] as number) <= 32768,
      ) ||
      !Number.isSafeInteger(v.fps) ||
      (v.fps as number) < 1 ||
      (v.fps as number) > 30
    )
      throw new Error("invalid_video_config");
  } else if (v.type === "frame") {
    if (
      !Number.isSafeInteger(v.seq) ||
      (v.seq as number) < 0 ||
      !Number.isSafeInteger(v.timestamp_us) ||
      (v.timestamp_us as number) < 0 ||
      typeof v.key !== "boolean" ||
      typeof v.data !== "string" ||
      !v.data.length ||
      v.data.length > 1_400_000 ||
      !/^[A-Za-z0-9+/]*={0,2}$/.test(v.data)
    )
      throw new Error("invalid_video_frame");
  } else throw new Error("invalid_video_packet");
  return v as unknown as VideoPacket;
}
