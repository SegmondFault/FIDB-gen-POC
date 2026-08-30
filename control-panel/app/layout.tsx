import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  metadataBase: new URL(process.env.SITE_URL ?? 'http://localhost:3000'),
  title: 'FIDB Factory Control Plane',
  description: 'Multi-worker operations, planning, and toolchain readiness for the FIDB factory.',
  openGraph: {
    title: 'FIDB Factory Control Plane',
    description: 'Multi-worker builds, toolchain readiness, and governed automation.',
    images: ['/og.png'],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'FIDB Factory Control Plane',
    description: 'Multi-worker builds, toolchain readiness, and governed automation.',
    images: ['/og.png'],
  },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
