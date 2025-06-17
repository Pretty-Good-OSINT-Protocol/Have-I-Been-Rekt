
import React from "react";
import { cn } from "@/lib/utils";

interface HeaderProps {
  className?: string;
}

export function Header({ className }: HeaderProps) {
  return (
    <header className={cn("w-full py-4 px-4", className)}>
      <div className="container max-w-6xl mx-auto flex items-center justify-between">
        <div className="flex items-center gap-3">
          <img
            src="/lovable-uploads/b3f5336e-7469-477f-b013-a66c76b18d49.png"
            alt="Have I Been REKT Logo"
            className="h-12 w-auto"
          />
          <div className="flex flex-col">
            <span className="font-extrabold text-2xl text-white leading-tight">
              HAVE I BEEN <span className="text-hibr-accent">REKT?</span>
            </span>
            <span className="text-xs text-hibr-muted-foreground">by Pretty Good OSINT Protocol</span>
          </div>
        </div>
      </div>
    </header>
  );
}
