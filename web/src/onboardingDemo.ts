export type OnboardingStatus = "enrolled" | "pending" | "never";

export type OnboardingDevice = {
  id: string;
  name: string;
  platform: "Windows" | "macOS" | "Linux" | "Android" | "iOS";
  last_seen: string | null;
  status: OnboardingStatus;
};

/** Static demo devices — no backend. */
export const DEMO_ONBOARDING_DEVICES: OnboardingDevice[] = [
  {
    id: "dev-win-01",
    name: "WIN-LAPTOP-042",
    platform: "Windows",
    last_seen: "2026-09-09T09:12:00Z",
    status: "enrolled",
  },
  {
    id: "dev-mac-01",
    name: "MacBook-Pro-Analyst",
    platform: "macOS",
    last_seen: "2026-09-09T08:55:00Z",
    status: "enrolled",
  },
  {
    id: "dev-and-01",
    name: "Pixel-7-SOC",
    platform: "Android",
    last_seen: null,
    status: "pending",
  },
  {
    id: "dev-ios-01",
    name: "iPhone-Field",
    platform: "iOS",
    last_seen: null,
    status: "never",
  },
];

export const AGENT_PLATFORMS = [
  "Windows",
  "macOS",
  "Linux",
  "Android",
  "iOS",
] as const;
