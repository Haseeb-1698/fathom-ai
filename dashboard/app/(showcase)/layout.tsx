"use client";

import { Sidebar } from "@/components/layout/sidebar";

export default function ShowcaseLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className="flex noise-overlay">
      <Sidebar />
      <main className="flex-1 ml-[72px] lg:ml-[240px] min-h-screen">
        {children}
      </main>
    </div>
  );
}
