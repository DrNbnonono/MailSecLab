import type { CSSProperties } from "react";

const paths = {
  mail: "M3 5h18v14H3z M3 6l9 7 9-7",
  arrow: "M5 12h14m-6-6 6 6-6 6",
  upload: "M12 16V3m-5 5 5-5 5 5M4 16v5h16v-5",
  file: "M6 3h8l4 4v14H6z M14 3v5h4 M9 12h6m-6 4h6",
  route:
    "M6 4v12a4 4 0 0 0 4 4h8 M6 4l-3 3m3-3 3 3 M18 20l-3-3m3 3-3 3 M18 4v9",
  clock: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18 M12 7v5l3 2",
  search: "M10.5 3a7.5 7.5 0 1 0 0 15 7.5 7.5 0 0 0 0-15 M16 16l5 5",
  download: "M12 3v13m-5-5 5 5 5-5M4 17v4h16v-4",
  check: "M5 12l4 4L19 6",
  alert: "M12 3 2 21h20L12 3 M12 9v5m0 3v1",
  close: "m6 6 12 12M6 18 18 6",
  layers: "m12 3 10 5-10 5L2 8 12 3 M2 12l10 5 10-5 M2 16l10 5 10-5",
} as const;

export function Icon({
  name,
  size = 18,
  style,
}: {
  name: keyof typeof paths;
  size?: number;
  style?: CSSProperties;
}) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      style={style}
    >
      <path d={paths[name]} />
    </svg>
  );
}
