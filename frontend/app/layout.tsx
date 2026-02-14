import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SHADOWPULSE - Security Command Center",
  description: "AI-Native Security Pentesting Command Center",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-sp-bg text-sp-text font-mono antialiased">
        {children}
      </body>
    </html>
  );
}
