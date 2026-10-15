import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "인프라 취약점 KEV 위협 현황",
  description: "CISA KEV 기반 인프라 영역별 실제 악용 취약점 대시보드",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="ko">
      <body>{children}</body>
    </html>
  );
}
