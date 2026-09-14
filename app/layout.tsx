import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  metadataBase: new URL("https://secchecker.cc"),
  title: "secchecker — trust boundaries for AI",
  description: "Local static analysis for AI, LLM, agent and MCP trust boundaries. Catch risky code paths before they ship.",
  alternates: { canonical: "/" },
  openGraph: {
    title: "secchecker — trust boundaries for AI",
    description: "Catch risky AI trust-boundary crossings before they ship.",
    url: "https://secchecker.cc",
    siteName: "secchecker",
    type: "website"
  },
  twitter: {
    card: "summary_large_image",
    title: "secchecker — trust boundaries for AI",
    description: "Local static analysis · No LLM judge · Zero runtime dependencies"
  }
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
