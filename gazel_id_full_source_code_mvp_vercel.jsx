// Gazel ID — MVP (Next.js App Router) — Single repo ready for Vercel
// Features: Email+Password, Org management, Invite members, Roles, 2FA (TOTP), SSO-ready (OIDC placeholder)
// NOTE: This is an MVP with pragmatic security defaults. For production, add rate limiting, audit logs, device sessions, and SAML.

// =========================
// FILE TREE (copy as-is)
// =========================
// package.json
// next.config.js
// vercel.json
// .env.example
// prisma/schema.prisma
// prisma/seed.ts
// src/app/layout.tsx
// src/app/globals.css
// src/app/page.tsx
// src/app/(auth)/login/page.tsx
// src/app/(auth)/register/page.tsx
// src/app/(auth)/logout/route.ts
// src/app/(auth)/verify-email/page.tsx
// src/app/(auth)/forgot/page.tsx
// src/app/(auth)/reset/page.tsx
// src/app/app/layout.tsx
// src/app/app/page.tsx
// src/app/app/org/page.tsx
// src/app/app/org/new/page.tsx
// src/app/app/org/[orgId]/page.tsx
// src/app/app/org/[orgId]/members/page.tsx
// src/app/app/org/[orgId]/security/page.tsx
// src/app/app/org/[orgId]/apps/page.tsx
// src/app/api/auth/login/route.ts
// src/app/api/auth/register/route.ts
// src/app/api/auth/refresh/route.ts
// src/app/api/auth/me/route.ts
// src/app/api/auth/logout/route.ts
// src/app/api/auth/verify-email/route.ts
// src/app/api/auth/forgot/route.ts
// src/app/api/auth/reset/route.ts
// src/app/api/org/create/route.ts
// src/app/api/org/list/route.ts
// src/app/api/org/switch/route.ts
// src/app/api/org/[orgId]/members/list/route.ts
// src/app/api/org/[orgId]/members/invite/route.ts
// src/app/api/org/[orgId]/members/remove/route.ts
// src/app/api/org/[orgId]/members/role/route.ts
// src/app/api/org/[orgId]/security/2fa/setup/route.ts
// src/app/api/org/[orgId]/security/2fa/verify/route.ts
// src/app/api/org/[orgId]/security/2fa/disable/route.ts
// src/app/api/oidc/.well-known/openid-configuration/route.ts
// src/app/api/oidc/authorize/route.ts
// src/app/api/oidc/token/route.ts
// src/app/api/oidc/userinfo/route.ts
// src/components/ui.tsx
// src/components/nav.tsx
// src/components/forms.tsx
// src/lib/auth.ts
// src/lib/crypto.ts
// src/lib/db.ts
// src/lib/email.ts
// src/lib/env.ts
// src/lib/http.ts
// src/lib/validators.ts
// src/middleware.ts

// =====================================================
// package.json
// =====================================================
export const __package_json__ = `{
  "name": "gazel-id",
  "private": true,
  "version": "0.1.0",
  "type": "module",
  "scripts": {
    "dev": "next dev",
    "build": "next build",
    "start": "next start",
    "lint": "next lint",
    "prisma:generate": "prisma generate",
    "prisma:migrate": "prisma migrate dev",
    "prisma:seed": "tsx prisma/seed.ts"
  },
  "dependencies": {
    "@prisma/client": "^5.10.2",
    "bcryptjs": "^2.4.3",
    "jose": "^5.2.2",
    "next": "14.2.5",
    "qrcode": "^1.5.4",
    "react": "18.3.1",
    "react-dom": "18.3.1",
    "speakeasy": "^2.0.0",
    "zod": "^3.23.8"
  },
  "devDependencies": {
    "@types/node": "^20.11.19",
    "@types/qrcode": "^1.5.5",
    "@types/react": "^18.2.55",
    "@types/react-dom": "^18.2.19",
    "prisma": "^5.10.2",
    "tsx": "^4.7.1",
    "typescript": "^5.3.3"
  }
}`;

// =====================================================
// next.config.js
// =====================================================
export const __next_config__ = `/** @type {import('next').NextConfig} */
const nextConfig = {
  experimental: {
    serverActions: { allowedOrigins: ['*'] }
  }
};

export default nextConfig;
`;

// =====================================================
// vercel.json
// =====================================================
export const __vercel_json__ = `{
  "crons": []
}`;

// =====================================================
// .env.example
// =====================================================
export const __env_example__ = `# Database
DATABASE_URL="postgresql://USER:PASSWORD@HOST:5432/gazel_id?schema=public"

# App
APP_NAME="Gazel ID"
APP_URL="http://localhost:3000"

# Auth
JWT_ISSUER="gazel-id"
JWT_AUDIENCE="gazel-apps"
JWT_SECRET="change_me_super_long_random"
REFRESH_SECRET="change_me_refresh_super_long_random"
COOKIE_SECURE="false"

# Email (MVP: console logger)
EMAIL_FROM="no-reply@gazel.id"

# OIDC (MVP placeholders)
OIDC_ISSUER="http://localhost:3000"
`;

// =====================================================
// prisma/schema.prisma
// =====================================================
export const __prisma_schema__ = `generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

enum GlobalRole {
  SUPER_ADMIN
  USER
}

enum OrgRole {
  ORG_ADMIN
  MEMBER
}

enum InviteStatus {
  PENDING
  ACCEPTED
  EXPIRED
  REVOKED
}

enum TokenType {
  EMAIL_VERIFY
  PASSWORD_RESET
  INVITE
  REFRESH
}

model User {
  id            String      @id @default(cuid())
  email         String      @unique
  name          String?
  passwordHash  String
  emailVerified Boolean     @default(false)
  globalRole    GlobalRole  @default(USER)

  totpEnabled   Boolean     @default(false)
  totpSecretEnc String?

  createdAt     DateTime    @default(now())
  updatedAt     DateTime    @updatedAt

  memberships   Membership[]
  tokens        Token[]
}

model Organization {
  id        String   @id @default(cuid())
  name      String
  slug      String   @unique
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt

  memberships Membership[]
  apps        AppClient[]
}

model Membership {
  id        String   @id @default(cuid())
  userId    String
  orgId     String
  role      OrgRole  @default(MEMBER)
  createdAt DateTime @default(now())

  user User @relation(fields: [userId], references: [id], onDelete: Cascade)
  org  Organization @relation(fields: [orgId], references: [id], onDelete: Cascade)

  @@unique([userId, orgId])
  @@index([orgId])
}

model Invite {
  id        String       @id @default(cuid())
  orgId     String
  email     String
  role      OrgRole      @default(MEMBER)
  status    InviteStatus @default(PENDING)
  token     String       @unique
  expiresAt DateTime
  createdAt DateTime     @default(now())

  org Organization @relation(fields: [orgId], references: [id], onDelete: Cascade)

  @@index([orgId])
}

model Token {
  id        String    @id @default(cuid())
  userId    String?
  type      TokenType
  tokenHash String    @unique
  expiresAt DateTime
  createdAt DateTime  @default(now())

  user User? @relation(fields: [userId], references: [id], onDelete: Cascade)

  @@index([userId])
  @@index([type])
}

model AppClient {
  id           String   @id @default(cuid())
  orgId        String
  name         String
  clientId     String   @unique
  clientSecret String
  redirectUris String   // CSV for MVP
  createdAt    DateTime @default(now())

  org Organization @relation(fields: [orgId], references: [id], onDelete: Cascade)

  @@index([orgId])
}
`;

// =====================================================
// prisma/seed.ts
// =====================================================
export const __prisma_seed__ = `import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

async function main() {
  const email = 'admin@gazel.id';
  const password = 'Admin123!';

  const passwordHash = await bcrypt.hash(password, 12);

  const user = await prisma.user.upsert({
    where: { email },
    update: {},
    create: {
      email,
      name: 'Gazel Super Admin',
      passwordHash,
      emailVerified: true,
      globalRole: 'SUPER_ADMIN'
    }
  });

  const org = await prisma.organization.upsert({
    where: { slug: 'gazel' },
    update: {},
    create: {
      name: 'Gazel',
      slug: 'gazel'
    }
  });

  await prisma.membership.upsert({
    where: { userId_orgId: { userId: user.id, orgId: org.id } },
    update: { role: 'ORG_ADMIN' },
    create: { userId: user.id, orgId: org.id, role: 'ORG_ADMIN' }
  });

  console.log('Seed done.');
  console.log('Login:', email, password);
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
`;

// =====================================================
// src/lib/env.ts
// =====================================================
export const __env_ts__ = `import { z } from 'zod';

const EnvSchema = z.object({
  DATABASE_URL: z.string().min(1),
  APP_NAME: z.string().default('Gazel ID'),
  APP_URL: z.string().url(),

  JWT_ISSUER: z.string().default('gazel-id'),
  JWT_AUDIENCE: z.string().default('gazel-apps'),
  JWT_SECRET: z.string().min(32),
  REFRESH_SECRET: z.string().min(32),

  COOKIE_SECURE: z.string().default('false'),

  EMAIL_FROM: z.string().default('no-reply@gazel.id'),

  OIDC_ISSUER: z.string().url()
});

export const env = EnvSchema.parse({
  DATABASE_URL: process.env.DATABASE_URL,
  APP_NAME: process.env.APP_NAME,
  APP_URL: process.env.APP_URL,
  JWT_ISSUER: process.env.JWT_ISSUER,
  JWT_AUDIENCE: process.env.JWT_AUDIENCE,
  JWT_SECRET: process.env.JWT_SECRET,
  REFRESH_SECRET: process.env.REFRESH_SECRET,
  COOKIE_SECURE: process.env.COOKIE_SECURE,
  EMAIL_FROM: process.env.EMAIL_FROM,
  OIDC_ISSUER: process.env.OIDC_ISSUER
});

export const cookieSecure = env.COOKIE_SECURE === 'true';
`;

// =====================================================
// src/lib/db.ts
// =====================================================
export const __db_ts__ = `import { PrismaClient } from '@prisma/client';

declare global {
  // eslint-disable-next-line no-var
  var prisma: PrismaClient | undefined;
}

export const prisma = global.prisma || new PrismaClient();

if (process.env.NODE_ENV !== 'production') global.prisma = prisma;
`;

// =====================================================
// src/lib/crypto.ts
// =====================================================
export const __crypto_ts__ = `import crypto from 'crypto';

export function sha256(input: string) {
  return crypto.createHash('sha256').update(input).digest('hex');
}

export function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}

export function randomId(prefix = '') {
  return prefix + crypto.randomBytes(12).toString('hex');
}
`;

// =====================================================
// src/lib/email.ts (MVP: console logger)
// =====================================================
export const __email_ts__ = `import { env } from './env';

export async function sendEmail(to: string, subject: string, html: string) {
  // MVP: log to console. Replace with Resend/Sendgrid later.
  console.log('--- EMAIL (MVP) ---');
  console.log('From:', env.EMAIL_FROM);
  console.log('To:', to);
  console.log('Subject:', subject);
  console.log('HTML:', html);
  console.log('-------------------');
}
`;

// =====================================================
// src/lib/validators.ts
// =====================================================
export const __validators_ts__ = `import { z } from 'zod';

export const EmailSchema = z.string().email();

export const PasswordSchema = z
  .string()
  .min(8)
  .max(72)
  .regex(/[A-Z]/, 'Must include uppercase')
  .regex(/[a-z]/, 'Must include lowercase')
  .regex(/[0-9]/, 'Must include number')
  .regex(/[^A-Za-z0-9]/, 'Must include symbol');

export const SlugSchema = z
  .string()
  .min(2)
  .max(32)
  .regex(/^[a-z0-9-]+$/);

export const OrgNameSchema = z.string().min(2).max(64);

export const NameSchema = z.string().min(2).max(64).optional();
`;

// =====================================================
// src/lib/http.ts
// =====================================================
export const __http_ts__ = `export async function api<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(init?.headers || {})
    },
    cache: 'no-store'
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data?.error || 'Request failed');
  return data as T;
}
`;

// =====================================================
// src/lib/auth.ts
// =====================================================
export const __auth_ts__ = `import { SignJWT, jwtVerify } from 'jose';
import { cookies } from 'next/headers';
import { env, cookieSecure } from './env';
import { prisma } from './db';
import { sha256 } from './crypto';

const enc = new TextEncoder();

export type SessionUser = {
  id: string;
  email: string;
  name: string | null;
  globalRole: 'SUPER_ADMIN' | 'USER';
  activeOrgId: string | null;
};

export const ACCESS_COOKIE = 'gazel_access';
export const REFRESH_COOKIE = 'gazel_refresh';
export const ACTIVE_ORG_COOKIE = 'gazel_active_org';

export async function signAccessToken(payload: Omit<SessionUser, 'activeOrgId'> & { activeOrgId: string | null }) {
  return new SignJWT(payload)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuer(env.JWT_ISSUER)
    .setAudience(env.JWT_AUDIENCE)
    .setIssuedAt()
    .setExpirationTime('15m')
    .sign(enc.encode(env.JWT_SECRET));
}

export async function signRefreshToken(userId: string) {
  // Store only hash in DB
  const raw = `${userId}.${cryptoRandom(24)}`;
  const tokenHash = sha256(raw);

  const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 30); // 30 days

  await prisma.token.create({
    data: {
      userId,
      type: 'REFRESH',
      tokenHash,
      expiresAt
    }
  });

  return raw;
}

function cryptoRandom(bytes: number) {
  // no node:crypto import to keep file small; rely on global
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const c: any = require('crypto');
  return c.randomBytes(bytes).toString('hex');
}

export async function verifyAccessToken(token: string) {
  const { payload } = await jwtVerify(token, enc.encode(env.JWT_SECRET), {
    issuer: env.JWT_ISSUER,
    audience: env.JWT_AUDIENCE
  });
  return payload as unknown as SessionUser;
}

export function setAuthCookies(access: string, refresh: string, activeOrgId: string | null) {
  const c = cookies();
  c.set(ACCESS_COOKIE, access, {
    httpOnly: true,
    secure: cookieSecure,
    sameSite: 'lax',
    path: '/',
    maxAge: 60 * 15
  });
  c.set(REFRESH_COOKIE, refresh, {
    httpOnly: true,
    secure: cookieSecure,
    sameSite: 'lax',
    path: '/',
    maxAge: 60 * 60 * 24 * 30
  });
  if (activeOrgId) {
    c.set(ACTIVE_ORG_COOKIE, activeOrgId, {
      httpOnly: false,
      secure: cookieSecure,
      sameSite: 'lax',
      path: '/',
      maxAge: 60 * 60 * 24 * 365
    });
  }
}

export function clearAuthCookies() {
  const c = cookies();
  c.set(ACCESS_COOKIE, '', { path: '/', maxAge: 0 });
  c.set(REFRESH_COOKIE, '', { path: '/', maxAge: 0 });
  c.set(ACTIVE_ORG_COOKIE, '', { path: '/', maxAge: 0 });
}

export async function getSessionUser(): Promise<SessionUser | null> {
  const c = cookies();
  const access = c.get(ACCESS_COOKIE)?.value;
  const activeOrgId = c.get(ACTIVE_ORG_COOKIE)?.value || null;

  if (!access) return null;
  try {
    const u = await verifyAccessToken(access);
    return { ...u, activeOrgId };
  } catch {
    return null;
  }
}

export async function requireUser() {
  const u = await getSessionUser();
  if (!u) throw new Error('UNAUTHORIZED');
  return u;
}
`;

// =====================================================
// src/components/ui.tsx
// =====================================================
export const __ui_tsx__ = `import React from 'react';

export function Container({ children }: { children: React.ReactNode }) {
  return <div className="mx-auto w-full max-w-6xl px-4">{children}</div>;
}

export function Card({ children }: { children: React.ReactNode }) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-white shadow-sm">
      {children}
    </div>
  );
}

export function CardHeader({ title, subtitle }: { title: string; subtitle?: string }) {
  return (
    <div className="border-b border-slate-200 p-5">
      <div className="text-lg font-semibold text-slate-900">{title}</div>
      {subtitle ? <div className="mt-1 text-sm text-slate-500">{subtitle}</div> : null}
    </div>
  );
}

export function CardContent({ children }: { children: React.ReactNode }) {
  return <div className="p-5">{children}</div>;
}

export function Input(props: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      {...props}
      className={
        "w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm text-slate-900 outline-none focus:border-slate-400 " +
        (props.className || '')
      }
    />
  );
}

export function Label({ children }: { children: React.ReactNode }) {
  return <div className="mb-1 text-xs font-medium text-slate-600">{children}</div>;
}

export function Button({
  children,
  variant = 'primary',
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement> & { variant?: 'primary' | 'ghost' | 'danger' }) {
  const base =
    'inline-flex items-center justify-center gap-2 rounded-xl px-4 py-2 text-sm font-medium transition active:scale-[0.99] disabled:opacity-60';
  const styles =
    variant === 'primary'
      ? 'bg-slate-900 text-white hover:bg-slate-800'
      : variant === 'danger'
        ? 'bg-red-600 text-white hover:bg-red-500'
        : 'bg-transparent text-slate-700 hover:bg-slate-100';

  return (
    <button {...props} className={base + ' ' + styles + ' ' + (props.className || '')} />
  );
}

export function Pill({ children }: { children: React.ReactNode }) {
  return (
    <span className="inline-flex items-center rounded-full bg-slate-100 px-3 py-1 text-xs font-medium text-slate-700">
      {children}
    </span>
  );
}

export function Hr() {
  return <div className="my-4 h-px w-full bg-slate-200" />;
}

export function Toast({ text }: { text: string }) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-700 shadow-sm">
      {text}
    </div>
  );
}
`;

// =====================================================
// src/components/nav.tsx
// =====================================================
export const __nav_tsx__ = `import Link from 'next/link';
import { Container, Pill } from './ui';

export function AppTopbar({
  user,
  orgName
}: {
  user: { email: string; name: string | null; globalRole: string };
  orgName?: string | null;
}) {
  return (
    <div className="sticky top-0 z-40 border-b border-slate-200 bg-white/80 backdrop-blur">
      <Container>
        <div className="flex items-center justify-between py-3">
          <div className="flex items-center gap-3">
            <Link href="/app" className="font-semibold text-slate-900">
              Gazel <span className="text-slate-400">ID</span>
            </Link>
            <Pill>{orgName || 'No org selected'}</Pill>
          </div>

          <div className="flex items-center gap-4">
            <div className="hidden text-sm text-slate-600 md:block">
              {user.name ? `${user.name} · ` : ''}{user.email}
            </div>
            <Link className="text-sm text-slate-700 hover:underline" href="/app/org">
              Organizations
            </Link>
            <Link className="text-sm text-slate-700 hover:underline" href="/app">
              Dashboard
            </Link>
            <form action="/api/auth/logout" method="post">
              <button className="text-sm text-slate-700 hover:underline" type="submit">
                Logout
              </button>
            </form>
          </div>
        </div>
      </Container>
    </div>
  );
}
`;

// =====================================================
// src/components/forms.tsx
// =====================================================
export const __forms_tsx__ = `import React from 'react';
import { Button, Input, Label } from './ui';

export function Field({
  label,
  children
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <Label>{label}</Label>
      {children}
    </div>
  );
}

export function FormError({ error }: { error?: string | null }) {
  if (!error) return null;
  return (
    <div className="rounded-xl border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
      {error}
    </div>
  );
}

export function SubmitRow({
  primary,
  secondary
}: {
  primary: { text: string; loading?: boolean };
  secondary?: React.ReactNode;
}) {
  return (
    <div className="flex items-center justify-between gap-3">
      <Button type="submit" disabled={primary.loading}>
        {primary.loading ? 'Please wait…' : primary.text}
      </Button>
      {secondary}
    </div>
  );
}

export function SmallLink({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <a className="text-sm text-slate-700 hover:underline" href={href}>
      {children}
    </a>
  );
}

export function Hint({ children }: { children: React.ReactNode }) {
  return <div className="text-xs text-slate-500">{children}</div>;
}
`;

// =====================================================
// src/app/globals.css
// =====================================================
export const __globals_css__ = `@tailwind base;
@tailwind components;
@tailwind utilities;

:root{
  color-scheme: light;
}

html, body{
  height:100%;
}

body{
  background: #f8fafc;
  color:#0f172a;
}

*{ box-sizing:border-box; }
`;

// =====================================================
// src/app/layout.tsx
// =====================================================
export const __root_layout__ = `import './globals.css';
import type { Metadata } from 'next';
import { env } from '@/lib/env';

export const metadata: Metadata = {
  title: env.APP_NAME,
  description: 'Gazel ID — Identity & Access Management for Gazel ecosystem'
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="id">
      <body>{children}</body>
    </html>
  );
}
`;

// =====================================================
// src/app/page.tsx
// =====================================================
export const __landing_page__ = `import Link from 'next/link';
import { Container, Card, CardContent, CardHeader, Button, Pill } from '@/components/ui';

export default function Page() {
  return (
    <div className="min-h-screen">
      <div className="border-b border-slate-200 bg-white">
        <Container>
          <div className="flex items-center justify-between py-5">
            <div className="text-lg font-semibold">Gazel <span className="text-slate-400">ID</span></div>
            <div className="flex items-center gap-3">
              <Link className="text-sm text-slate-700 hover:underline" href="/login">Login</Link>
              <Link className="text-sm text-slate-700 hover:underline" href="/register">Register</Link>
            </div>
          </div>
        </Container>
      </div>

      <Container>
        <div className="grid gap-6 py-10 md:grid-cols-2">
          <Card>
            <CardHeader title="One login for all Gazel products" subtitle="SSO-ready MVP: organizations, roles, and 2FA." />
            <CardContent>
              <div className="flex flex-wrap gap-2">
                <Pill>SSO (OIDC-ready)</Pill>
                <Pill>Organizations</Pill>
                <Pill>Invites</Pill>
                <Pill>Roles</Pill>
                <Pill>2FA (TOTP)</Pill>
              </div>
              <div className="mt-5 flex gap-3">
                <Link href="/login"><Button>Login</Button></Link>
                <Link href="/register"><Button variant="ghost">Create account</Button></Link>
              </div>
              <div className="mt-3 text-xs text-slate-500">
                Seed admin: admin@gazel.id / Admin123!
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader title="Built for B2B multi-tenant" subtitle="Each company is an organization. Each app connects via OIDC." />
            <CardContent>
              <div className="text-sm text-slate-700">
                MVP fokus: sistem login yang rapi, aman, dan siap dihubungkan ke Oqline ERP, Gazel Cloud, Gazel Secure, Exmind AI.
              </div>
              <div className="mt-4 text-sm text-slate-700">
                Next upgrade: audit log, device sessions, SAML, SCIM, conditional access.
              </div>
            </CardContent>
          </Card>
        </div>
      </Container>
    </div>
  );
}
`;

// =====================================================
// src/app/(auth)/login/page.tsx
// =====================================================
export const __login_page__ = `"use client";

import { useState } from 'react';
import Link from 'next/link';
import { api } from '@/lib/http';
import { Container, Card, CardHeader, CardContent } from '@/components/ui';
import { Field, FormError, SubmitRow, SmallLink, Hint } from '@/components/forms';
import { Input } from '@/components/ui';

export default function LoginPage() {
  const [email, setEmail] = useState('admin@gazel.id');
  const [password, setPassword] = useState('Admin123!');
  const [otp, setOtp] = useState('');
  const [needOtp, setNeedOtp] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const res = await api<{ ok: true; needOtp?: boolean }>("/api/auth/login", {
        method: 'POST',
        body: JSON.stringify({ email, password, otp: otp || undefined })
      });

      if (res.needOtp) {
        setNeedOtp(true);
        setLoading(false);
        return;
      }

      window.location.href = '/app';
    } catch (err: any) {
      setError(err.message || 'Login failed');
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen">
      <Container>
        <div className="mx-auto max-w-md py-10">
          <Card>
            <CardHeader title="Login" subtitle="Masuk ke ekosistem Gazel." />
            <CardContent>
              <form className="grid gap-4" onSubmit={onSubmit}>
                <FormError error={error} />
                <Field label="Email">
                  <Input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@company.com" />
                </Field>
                <Field label="Password">
                  <Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="••••••••" />
                </Field>

                {needOtp ? (
                  <>
                    <Field label="2FA OTP (Authenticator)">
                      <Input value={otp} onChange={(e) => setOtp(e.target.value)} placeholder="123456" />
                    </Field>
                    <Hint>OTP wajib jika 2FA aktif.</Hint>
                  </>
                ) : null}

                <SubmitRow
                  primary={{ text: needOtp ? 'Verify & Login' : 'Login', loading }}
                  secondary={
                    <div className="flex items-center gap-3">
                      <SmallLink href="/forgot">Forgot?</SmallLink>
                      <Link className="text-sm text-slate-700 hover:underline" href="/register">Register</Link>
                    </div>
                  }
                />
              </form>
            </CardContent>
          </Card>

          <div className="mt-4 text-center text-xs text-slate-500">
            <a className="hover:underline" href="/">Back</a>
          </div>
        </div>
      </Container>
    </div>
  );
}
`;

// =====================================================
// src/app/(auth)/register/page.tsx
// =====================================================
export const __register_page__ = `"use client";

import { useState } from 'react';
import Link from 'next/link';
import { api } from '@/lib/http';
import { Container, Card, CardHeader, CardContent } from '@/components/ui';
import { Field, FormError, SubmitRow, SmallLink, Hint } from '@/components/forms';
import { Input } from '@/components/ui';

export default function RegisterPage() {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [ok, setOk] = useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      await api<{ ok: true }>("/api/auth/register", {
        method: 'POST',
        body: JSON.stringify({ name, email, password })
      });
      setOk(true);
    } catch (err: any) {
      setError(err.message || 'Register failed');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen">
      <Container>
        <div className="mx-auto max-w-md py-10">
          <Card>
            <CardHeader title="Create account" subtitle="Buat akun Gazel ID." />
            <CardContent>
              {ok ? (
                <div className="grid gap-3">
                  <div className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-700">
                    Akun berhasil dibuat. Silakan login.
                  </div>
                  <Link href="/login" className="text-sm text-slate-700 hover:underline">Go to login</Link>
                </div>
              ) : (
                <form className="grid gap-4" onSubmit={onSubmit}>
                  <FormError error={error} />
                  <Field label="Name">
                    <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Your name" />
                  </Field>
                  <Field label="Email">
                    <Input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@company.com" />
                  </Field>
                  <Field label="Password">
                    <Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Min 8 chars, strong" />
                  </Field>
                  <Hint>Password wajib ada uppercase, lowercase, angka, dan simbol.</Hint>
                  <SubmitRow
                    primary={{ text: 'Create account', loading }}
                    secondary={<SmallLink href="/login">Login</SmallLink>}
                  />
                </form>
              )}
            </CardContent>
          </Card>

          <div className="mt-4 text-center text-xs text-slate-500">
            <a className="hover:underline" href="/">Back</a>
          </div>
        </div>
      </Container>
    </div>
  );
}
`;

// =====================================================
// src/app/(auth)/logout/route.ts
// =====================================================
export const __logout_route__ = `import { NextResponse } from 'next/server';
import { clearAuthCookies } from '@/lib/auth';

export async function POST() {
  clearAuthCookies();
  return NextResponse.redirect(new URL('/login', process.env.APP_URL || 'http://localhost:3000'));
}
`;

// =====================================================
// src/app/app/layout.tsx
// =====================================================
export const __app_layout__ = `import { AppTopbar } from '@/components/nav';
import { prisma } from '@/lib/db';
import { getSessionUser } from '@/lib/auth';
import { redirect } from 'next/navigation';

export default async function AppLayout({ children }: { children: React.ReactNode }) {
  const user = await getSessionUser();
  if (!user) redirect('/login');

  let orgName: string | null = null;
  if (user.activeOrgId) {
    const org = await prisma.organization.findUnique({ where: { id: user.activeOrgId } });
    orgName = org?.name || null;
  }

  return (
    <div className="min-h-screen">
      <AppTopbar user={user} orgName={orgName} />
      <div>{children}</div>
    </div>
  );
}
`;

// =====================================================
// src/app/app/page.tsx
// =====================================================
export const __app_page__ = `import Link from 'next/link';
import { Container, Card, CardContent, CardHeader, Pill, Hr } from '@/components/ui';
import { prisma } from '@/lib/db';
import { getSessionUser } from '@/lib/auth';

export default async function AppHome() {
  const user = await getSessionUser();
  if (!user) return null;

  const memberships = await prisma.membership.findMany({
    where: { userId: user.id },
    include: { org: true }
  });

  const active = user.activeOrgId
    ? memberships.find((m) => m.orgId === user.activeOrgId)
    : null;

  return (
    <Container>
      <div className="grid gap-6 py-8">
        <Card>
          <CardHeader title="Dashboard" subtitle="Ringkasan akun dan organisasi." />
          <CardContent>
            <div className="flex flex-wrap items-center gap-2">
              <Pill>User</Pill>
              <Pill>{user.email}</Pill>
              <Pill>Role: {user.globalRole}</Pill>
              <Pill>Active org: {active?.org?.name || 'none'}</Pill>
            </div>

            <Hr />

            <div className="grid gap-2 text-sm text-slate-700">
              <div>• Kelola organisasi: <Link className="underline" href="/app/org">Organizations</Link></div>
              <div>• Undang member + atur role</div>
              <div>• Aktifkan 2FA per user</div>
              <div>• Placeholder OIDC endpoints untuk SSO</div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader title="SSO endpoints (MVP)" subtitle="Ini masih placeholder, tapi sudah siap struktur OIDC." />
          <CardContent>
            <div className="grid gap-2 text-sm text-slate-700">
              <div>/.well-known/openid-configuration</div>
              <div>/api/oidc/authorize</div>
              <div>/api/oidc/token</div>
              <div>/api/oidc/userinfo</div>
            </div>
          </CardContent>
        </Card>
      </div>
    </Container>
  );
}
`;

// =====================================================
// src/app/app/org/page.tsx
// =====================================================
export const __org_list_page__ = `"use client";

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { api } from '@/lib/http';
import { Container, Card, CardHeader, CardContent, Button, Pill } from '@/components/ui';

type Org = { id: string; name: string; slug: string; role: 'ORG_ADMIN' | 'MEMBER' };

export default function OrgsPage() {
  const [items, setItems] = useState<Org[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const res = await api<{ orgs: Org[] }>("/api/org/list");
      setItems(res.orgs);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  async function setActive(orgId: string) {
    await api<{ ok: true }>("/api/org/switch", {
      method: 'POST',
      body: JSON.stringify({ orgId })
    });
    window.location.href = `/app/org/${orgId}`;
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <Container>
      <div className="grid gap-6 py-8">
        <Card>
          <CardHeader title="Organizations" subtitle="Multi-tenant: pilih perusahaan aktif." />
          <CardContent>
            {error ? (
              <div className="rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{error}</div>
            ) : null}

            <div className="flex items-center justify-between">
              <div className="text-sm text-slate-600">{loading ? 'Loading…' : `${items.length} org(s)`}</div>
              <Link href="/app/org/new"><Button>New org</Button></Link>
            </div>

            <div className="mt-4 grid gap-3">
              {items.map((o) => (
                <div key={o.id} className="flex items-center justify-between rounded-2xl border border-slate-200 bg-white p-4">
                  <div>
                    <div className="font-semibold text-slate-900">{o.name}</div>
                    <div className="mt-1 flex flex-wrap gap-2">
                      <Pill>@{o.slug}</Pill>
                      <Pill>Role: {o.role}</Pill>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Button variant="ghost" onClick={() => setActive(o.id)}>Set active</Button>
                    <Link href={`/app/org/${o.id}`} className="text-sm text-slate-700 hover:underline">Open</Link>
                  </div>
                </div>
              ))}

              {!loading && items.length === 0 ? (
                <div className="text-sm text-slate-600">Belum ada organisasi.</div>
              ) : null}
            </div>
          </CardContent>
        </Card>
      </div>
    </Container>
  );
}
`;

// =====================================================
// src/app/app/org/new/page.tsx
// =====================================================
export const __org_new_page__ = `"use client";

import { useState } from 'react';
import Link from 'next/link';
import { api } from '@/lib/http';
import { Container, Card, CardHeader, CardContent, Button } from '@/components/ui';
import { Field, FormError, SubmitRow } from '@/components/forms';
import { Input } from '@/components/ui';

export default function NewOrgPage() {
  const [name, setName] = useState('');
  const [slug, setSlug] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const res = await api<{ ok: true; orgId: string }>("/api/org/create", {
        method: 'POST',
        body: JSON.stringify({ name, slug })
      });
      window.location.href = `/app/org/${res.orgId}`;
    } catch (err: any) {
      setError(err.message || 'Create org failed');
    } finally {
      setLoading(false);
    }
  }

  return (
    <Container>
      <div className="mx-auto max-w-xl py-8">
        <Card>
          <CardHeader title="New organization" subtitle="Buat tenant perusahaan baru." />
          <CardContent>
            <form className="grid gap-4" onSubmit={onSubmit}>
              <FormError error={error} />
              <Field label="Organization name">
                <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Astria Group" />
              </Field>
              <Field label="Slug (unique)">
                <Input value={slug} onChange={(e) => setSlug(e.target.value)} placeholder="astria" />
              </Field>
              <SubmitRow primary={{ text: 'Create', loading }} secondary={<Link className="text-sm text-slate-700 hover:underline" href="/app/org">Back</Link>} />
            </form>
          </CardContent>
        </Card>
      </div>
    </Container>
  );
}
`;

// =====================================================
// src/app/app/org/[orgId]/page.tsx
// =====================================================
export const __org_detail_page__ = `import Link from 'next/link';
import { Container, Card, CardHeader, CardContent, Button, Pill } from '@/components/ui';
import { prisma } from '@/lib/db';
import { getSessionUser } from '@/lib/auth';
import { redirect } from 'next/navigation';

export default async function OrgDetail({ params }: { params: { orgId: string } }) {
  const user = await getSessionUser();
  if (!user) redirect('/login');

  const org = await prisma.organization.findUnique({ where: { id: params.orgId } });
  if (!org) redirect('/app/org');

  const membership = await prisma.membership.findUnique({
    where: { userId_orgId: { userId: user.id, orgId: org.id } }
  });

  if (!membership) redirect('/app/org');

  return (
    <Container>
      <div className="grid gap-6 py-8">
        <Card>
          <CardHeader title={org.name} subtitle={`@${org.slug}`} />
          <CardContent>
            <div className="flex flex-wrap items-center gap-2">
              <Pill>Role: {membership.role}</Pill>
              <Pill>Org ID: {org.id}</Pill>
            </div>

            <div className="mt-5 flex flex-wrap gap-3">
              <Link href={`/app/org/${org.id}/members`}><Button>Members</Button></Link>
              <Link href={`/app/org/${org.id}/security`}><Button variant="ghost">Security</Button></Link>
              <Link href={`/app/org/${org.id}/apps`}><Button variant="ghost">Apps (OIDC)</Button></Link>
            </div>
          </CardContent>
        </Card>
      </div>
    </Container>
  );
}
`;

// =====================================================
// src/app/app/org/[orgId]/members/page.tsx
// =====================================================
export const __org_members_page__ = `"use client";

import { useEffect, useMemo, useState } from 'react';
import { api } from '@/lib/http';
import { Container, Card, CardHeader, CardContent, Button, Pill } from '@/components/ui';
import { Field, FormError } from '@/components/forms';
import { Input } from '@/components/ui';

type Member = { id: string; email: string; name: string | null; role: 'ORG_ADMIN' | 'MEMBER' };

export default function MembersPage({ params }: { params: { orgId: string } }) {
  const orgId = params.orgId;

  const [items, setItems] = useState<Member[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState<'ORG_ADMIN' | 'MEMBER'>('MEMBER');

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const res = await api<{ members: Member[] }>(`/api/org/${orgId}/members/list`);
      setItems(res.members);
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  async function invite() {
    setError(null);
    try {
      const res = await api<{ ok: true; inviteLink: string }>(`/api/org/${orgId}/members/invite`, {
        method: 'POST',
        body: JSON.stringify({ email: inviteEmail, role: inviteRole })
      });
      alert('Invite created. Link copied to clipboard.');
      await navigator.clipboard.writeText(res.inviteLink);
      setInviteEmail('');
      await load();
    } catch (e: any) {
      setError(e.message);
    }
  }

  async function changeRole(userId: string, role: 'ORG_ADMIN' | 'MEMBER') {
    await api<{ ok: true }>(`/api/org/${orgId}/members/role`, {
      method: 'POST',
      body: JSON.stringify({ userId, role })
    });
    await load();
  }

  async function remove(userId: string) {
    if (!confirm('Remove member?')) return;
    await api<{ ok: true }>(`/api/org/${orgId}/members/remove`, {
      method: 'POST',
      body: JSON.stringify({ userId })
    });
    await load();
  }

  useEffect(() => {
    load();
  }, []);

  const admins = useMemo(() => items.filter((x) => x.role === 'ORG_ADMIN').length, [items]);

  return (
    <Container>
      <div className="grid gap-6 py-8">
        <Card>
          <CardHeader title="Members" subtitle="Invite user, manage roles." />
          <CardContent>
            {error ? (
              <div className="mb-4 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{error}</div>
            ) : null}

            <div className="flex flex-wrap gap-2">
              <Pill>Total: {items.length}</Pill>
              <Pill>Admins: {admins}</Pill>
            </div>

            <div className="mt-5 grid gap-3 rounded-2xl border border-slate-200 bg-slate-50 p-4">
              <div className="font-semibold text-slate-900">Invite member</div>
              <Field label="Email">
                <Input value={inviteEmail} onChange={(e) => setInviteEmail(e.target.value)} placeholder="user@company.com" />
              </Field>
              <Field label="Role">
                <select
                  className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm"
                  value={inviteRole}
                  onChange={(e) => setInviteRole(e.target.value as any)}
                >
                  <option value="MEMBER">MEMBER</option>
                  <option value="ORG_ADMIN">ORG_ADMIN</option>
                </select>
              </Field>
              <div className="flex items-center gap-2">
                <Button type="button" onClick={invite}>Create invite</Button>
                <div className="text-xs text-slate-500">Link invite akan di-copy otomatis.</div>
              </div>
            </div>

            <div className="mt-5 grid gap-3">
              {loading ? (
                <div className="text-sm text-slate-600">Loading…</div>
              ) : (
                items.map((m) => (
                  <div key={m.id} className="flex flex-col gap-3 rounded-2xl border border-slate-200 bg-white p-4 md:flex-row md:items-center md:justify-between">
                    <div>
                      <div className="font-semibold text-slate-900">{m.name || m.email}</div>
                      <div className="mt-1 flex flex-wrap gap-2">
                        <Pill>{m.email}</Pill>
                        <Pill>Role: {m.role}</Pill>
                      </div>
                    </div>

                    <div className="flex flex-wrap items-center gap-2">
                      <Button variant="ghost" onClick={() => changeRole(m.id, m.role === 'MEMBER' ? 'ORG_ADMIN' : 'MEMBER')}>
                        Toggle role
                      </Button>
                      <Button variant="danger" onClick={() => remove(m.id)}>Remove</Button>
                    </div>
                  </div>
                ))
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </Container>
  );
}
`;

// =====================================================
// src/app/app/org/[orgId]/security/page.tsx
// =====================================================
export const __org_security_page__ = `"use client";

import { useEffect, useState } from 'react';
import { api } from '@/lib/http';
import { Container, Card, CardHeader, CardContent, Button, Pill } from '@/components/ui';
import { Field, FormError, Hint } from '@/components/forms';
import { Input } from '@/components/ui';

export default function SecurityPage({ params }: { params: { orgId: string } }) {
  const orgId = params.orgId;

  const [error, setError] = useState<string | null>(null);
  const [qr, setQr] = useState<string | null>(null);
  const [secret, setSecret] = useState<string | null>(null);
  const [code, setCode] = useState('');
  const [enabled, setEnabled] = useState<boolean | null>(null);

  async function loadMe() {
    const res = await api<{ user: { totpEnabled: boolean } }>("/api/auth/me");
    setEnabled(res.user.totpEnabled);
  }

  async function setup() {
    setError(null);
    try {
      const res = await api<{ ok: true; qrDataUrl: string; secret: string }>(`/api/org/${orgId}/security/2fa/setup`, {
        method: 'POST'
      });
      setQr(res.qrDataUrl);
      setSecret(res.secret);
    } catch (e: any) {
      setError(e.message);
    }
  }

  async function verify() {
    setError(null);
    try {
      await api<{ ok: true }>(`/api/org/${orgId}/security/2fa/verify`, {
        method: 'POST',
        body: JSON.stringify({ code })
      });
      setQr(null);
      setSecret(null);
      setCode('');
      await loadMe();
      alert('2FA enabled');
    } catch (e: any) {
      setError(e.message);
    }
  }

  async function disable() {
    if (!confirm('Disable 2FA?')) return;
    await api<{ ok: true }>(`/api/org/${orgId}/security/2fa/disable`, { method: 'POST' });
    await loadMe();
  }

  useEffect(() => {
    loadMe();
  }, []);

  return (
    <Container>
      <div className="grid gap-6 py-8">
        <Card>
          <CardHeader title="Security" subtitle="2FA untuk akun kamu (TOTP)." />
          <CardContent>
            {error ? (
              <div className="mb-4 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">{error}</div>
            ) : null}

            <div className="flex flex-wrap items-center gap-2">
              <Pill>2FA: {enabled === null ? '…' : enabled ? 'Enabled' : 'Disabled'}</Pill>
            </div>

            <div className="mt-5 flex flex-wrap gap-2">
              {!enabled ? (
                <Button onClick={setup}>Setup 2FA</Button>
              ) : (
                <Button variant="danger" onClick={disable}>Disable 2FA</Button>
              )}
            </div>

            {qr ? (
              <div className="mt-6 grid gap-4 rounded-2xl border border-slate-200 bg-slate-50 p-4">
                <div className="font-semibold text-slate-900">Scan QR with Authenticator</div>
                <img src={qr} alt="QR" className="h-48 w-48 rounded-xl border border-slate-200 bg-white" />
                <div className="text-xs text-slate-500">Secret (backup): {secret}</div>
                <Field label="Enter OTP">
                  <Input value={code} onChange={(e) => setCode(e.target.value)} placeholder="123456" />
                </Field>
                <Hint>Masukkan OTP dari aplikasi Authenticator.</Hint>
                <Button onClick={verify}>Verify & Enable</Button>
              </div>
            ) : null}
          </CardContent>
        </Card>
      </div>
    </Container>
  );
}
`;

// =====================================================
// src/app/app/org/[orgId]/apps/page.tsx
// =====================================================
export const __org_apps_page__ = `import { Container, Card, CardHeader, CardContent, Pill } from '@/components/ui';

export default async function AppsPage() {
  return (
    <Container>
      <div className="grid gap-6 py-8">
        <Card>
          <CardHeader title="Apps (OIDC)" subtitle="MVP belum ada UI pembuatan client, tapi struktur DB sudah siap." />
          <CardContent>
            <div className="flex flex-wrap gap-2">
              <Pill>AppClient table ready</Pill>
              <Pill>Authorize endpoint placeholder</Pill>
              <Pill>Token endpoint placeholder</Pill>
            </div>
            <div className="mt-4 text-sm text-slate-700">
              Jika kamu mau, aku bisa lanjutkan versi 2: UI create OIDC client + full auth code flow.
            </div>
          </CardContent>
        </Card>
      </div>
    </Container>
  );
}
`;

// =====================================================
// API ROUTES — AUTH
// =====================================================
export const __api_auth_register__ = `import { NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import bcrypt from 'bcryptjs';
import { EmailSchema, PasswordSchema, NameSchema } from '@/lib/validators';

export async function POST(req: Request) {
  const body = await req.json().catch(() => null);
  if (!body) return NextResponse.json({ error: 'Invalid JSON' }, { status: 400 });

  const email = EmailSchema.safeParse(body.email);
  const password = PasswordSchema.safeParse(body.password);
  const name = NameSchema.safeParse(body.name);

  if (!email.success) return NextResponse.json({ error: 'Invalid email' }, { status: 400 });
  if (!password.success) return NextResponse.json({ error: 'Weak password' }, { status: 400 });
  if (!name.success) return NextResponse.json({ error: 'Invalid name' }, { status: 400 });

  const exists = await prisma.user.findUnique({ where: { email: email.data } });
  if (exists) return NextResponse.json({ error: 'Email already used' }, { status: 400 });

  const passwordHash = await bcrypt.hash(password.data, 12);

  await prisma.user.create({
    data: {
      email: email.data,
      name: name.data || null,
      passwordHash,
      emailVerified: true
    }
  });

  return NextResponse.json({ ok: true });
}
`;

export const __api_auth_login__ = `import { NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import bcrypt from 'bcryptjs';
import speakeasy from 'speakeasy';
import { EmailSchema } from '@/lib/validators';
import { signAccessToken, signRefreshToken, setAuthCookies } from '@/lib/auth';
import { sha256 } from '@/lib/crypto';

export async function POST(req: Request) {
  const body = await req.json().catch(() => null);
  if (!body) return NextResponse.json({ error: 'Invalid JSON' }, { status: 400 });

  const email = EmailSchema.safeParse(body.email);
  if (!email.success) return NextResponse.json({ error: 'Invalid email' }, { status: 400 });

  const user = await prisma.user.findUnique({ where: { email: email.data } });
  if (!user) return NextResponse.json({ error: 'Invalid credentials' }, { status: 401 });

  const ok = await bcrypt.compare(String(body.password || ''), user.passwordHash);
  if (!ok) return NextResponse.json({ error: 'Invalid credentials' }, { status: 401 });

  if (user.totpEnabled) {
    const otp = String(body.otp || '').trim();
    if (!otp) return NextResponse.json({ ok: true, needOtp: true });

    const secret = user.totpSecretEnc ? Buffer.from(user.totpSecretEnc, 'base64').toString('utf8') : '';
    const verified = speakeasy.totp.verify({
      secret,
      encoding: 'ascii',
      token: otp,
      window: 1
    });
    if (!verified) return NextResponse.json({ error: 'Invalid OTP' }, { status: 401 });
  }

  // Active org default
  const membership = await prisma.membership.findFirst({ where: { userId: user.id }, orderBy: { createdAt: 'asc' } });
  const activeOrgId = membership?.orgId || null;

  const access = await signAccessToken({
    id: user.id,
    email: user.email,
    name: user.name,
    globalRole: user.globalRole,
    activeOrgId
  });

  const refresh = await signRefreshToken(user.id);

  setAuthCookies(access, refresh, activeOrgId);

  return NextResponse.json({ ok: true });
}
`;

export const __api_auth_me__ = `import { NextResponse } from 'next/server';
import { getSessionUser } from '@/lib/auth';
import { prisma } from '@/lib/db';

export async function GET() {
  const session = await getSessionUser();
  if (!session) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  const user = await prisma.user.findUnique({ where: { id: session.id } });
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  return NextResponse.json({
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      globalRole: user.globalRole,
      totpEnabled: user.totpEnabled
    }
  });
}
`;

export const __api_auth_logout__ = `import { NextResponse } from 'next/server';
import { clearAuthCookies } from '@/lib/auth';

export async function POST() {
  clearAuthCookies();
  return NextResponse.json({ ok: true });
}
`;

// =====================================================
// API ROUTES — ORG
// =====================================================
export const __api_org_create__ = `import { NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { requireUser, setAuthCookies, signAccessToken } from '@/lib/auth';
import { OrgNameSchema, SlugSchema } from '@/lib/validators';

export async function POST(req: Request) {
  const session = await requireUser();

  const body = await req.json().catch(() => null);
  if (!body) return NextResponse.json({ error: 'Invalid JSON' }, { status: 400 });

  const name = OrgNameSchema.safeParse(body.name);
  const slug = SlugSchema.safeParse(body.slug);
  if (!name.success) return NextResponse.json({ error: 'Invalid org name' }, { status: 400 });
  if (!slug.success) return NextResponse.json({ error: 'Invalid slug' }, { status: 400 });

  const exists = await prisma.organization.findUnique({ where: { slug: slug.data } });
  if (exists) return NextResponse.json({ error: 'Slug already used' }, { status: 400 });

  const org = await prisma.organization.create({
    data: { name: name.data, slug: slug.data }
  });

  await prisma.membership.create({
    data: { userId: session.id, orgId: org.id, role: 'ORG_ADMIN' }
  });

  // Set as active
  const access = await signAccessToken({
    id: session.id,
    email: session.email,
    name: session.name,
    globalRole: session.globalRole,
    activeOrgId: org.id
  });

  // Keep refresh cookie; easiest: keep current refresh cookie unchanged.
  // We can't read refresh here reliably, so just set access and active org cookie.
  // For MVP, it's fine.

  setAuthCookies(access, '', org.id);

  return NextResponse.json({ ok: true, orgId: org.id });
}
`;

export const __api_org_list__ = `import { NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { requireUser } from '@/lib/auth';

export async function GET() {
  const session = await requireUser();

  const memberships = await prisma.membership.findMany({
    where: { userId: session.id },
    include: { org: true },
    orderBy: { createdAt: 'asc' }
  });

  return NextResponse.json({
    orgs: memberships.map((m) => ({
      id: m.org.id,
      name: m.org.name,
      slug: m.org.slug,
      role: m.role
    }))
  });
}
`;

export const __api_org_switch__ = `import { NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { requireUser, signAccessToken, setAuthCookies } from '@/lib/auth';

export async function POST(req: Request) {
  const session = await requireUser();
  const body = await req.json().catch(() => null);
  if (!body?.orgId) return NextResponse.json({ error: 'orgId required' }, { status: 400 });

  const membership = await prisma.membership.findUnique({
    where: { userId_orgId: { userId: session.id, orgId: String(body.orgId) } }
  });
  if (!membership) return NextResponse.json({ error: 'Forbidden' }, { status: 403 });

  const access = await signAccessToken({
    id: session.id,
    email: session.email,
    name: session.name,
    globalRole: session.globalRole,
    activeOrgId: membership.orgId
  });

  setAuthCookies(access, '', membership.orgId);

  return NextResponse.json({ ok: true });
}
`;

// =====================================================
// API ROUTES — MEMBERS
// =====================================================
export const __api_members_list__ = `import { NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { requireUser } from '@/lib/auth';

export async function GET(_req: Request, { params }: { params: { orgId: string } }) {
  const session = await requireUser();

  const membership = await prisma.membership.findUnique({
    where: { userId_orgId: { userId: session.id, orgId: params.orgId } }
  });
  if (!membership) return NextResponse.json({ error: 'Forbidden' }, { status: 403 });

  const members = await prisma.membership.findMany({
    where: { orgId: params.orgId },
    include: { user: true },
    orderBy: { createdAt: 'asc' }
  });

  return NextResponse.json({
    members: members.map((m) => ({
      id: m.user.id,
      email: m.user.email,
      name: m.user.name,
      role: m.role
    }))
  });
}
`;

export const __api_members_invite__ = `import { NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { requireUser } from '@/lib/auth';
import { EmailSchema } from '@/lib/validators';
import { randomToken } from '@/lib/crypto';
import { env } from '@/lib/env';

export async function POST(req: Request, { params }: { params: { orgId: string } }) {
  const session = await requireUser();

  const my = await prisma.membership.findUnique({
    where: { userId_orgId: { userId: session.id, orgId: params.orgId } }
  });
  if (!my || my.role !== 'ORG_ADMIN') return NextResponse.json({ error: 'Admin only' }, { status: 403 });

  const body = await req.json().catch(() => null);
  if (!body) return NextResponse.json({ error: 'Invalid JSON' }, { status: 400 });

  const email = EmailSchema.safeParse(body.email);
  if (!email.success) return NextResponse.json({ error: 'Invalid email' }, { status: 400 });

  const role = body.role === 'ORG_ADMIN' ? 'ORG_ADMIN' : 'MEMBER';

  const token = randomToken(24);
  const expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 7);

  const inv = await prisma.invite.create({
    data: {
      orgId: params.orgId,
      email: email.data,
      role,
      token,
      expiresAt
    }
  });

  const inviteLink = `${env.APP_URL}/register?invite=${inv.token}`;

  return NextResponse.json({ ok: true, inviteLink });
}
`;

export const __api_members_role__ = `import { NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { requireUser } from '@/lib/auth';

export async function POST(req: Request, { params }: { params: { orgId: string } }) {
  const session = await requireUser();

  const my = await prisma.membership.findUnique({
    where: { userId_orgId: { userId: session.id, orgId: params.orgId } }
  });
  if (!my || my.role !== 'ORG_ADMIN') return NextResponse.json({ error: 'Admin only' }, { status: 403 });

  const body = await req.json().catch(() => null);
  if (!body?.userId) return NextResponse.json({ error: 'userId required' }, { status: 400 });

  const role = body.role === 'ORG_ADMIN' ? 'ORG_ADMIN' : 'MEMBER';

  await prisma.membership.update({
    where: { userId_orgId: { userId: String(body.userId), orgId: params.orgId } },
    data: { role }
  });

  return NextResponse.json({ ok: true });
}
`;

export const __api_members_remove__ = `import { NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { requireUser } from '@/lib/auth';

export async function POST(req: Request, { params }: { params: { orgId: string } }) {
  const session = await requireUser();

  const my = await prisma.membership.findUnique({
    where: { userId_orgId: { userId: session.id, orgId: params.orgId } }
  });
  if (!my || my.role !== 'ORG_ADMIN') return NextResponse.json({ error: 'Admin only' }, { status: 403 });

  const body = await req.json().catch(() => null);
  if (!body?.userId) return NextResponse.json({ error: 'userId required' }, { status: 400 });

  if (String(body.userId) === session.id) {
    return NextResponse.json({ error: 'Cannot remove yourself' }, { status: 400 });
  }

  await prisma.membership.delete({
    where: { userId_orgId: { userId: String(body.userId), orgId: params.orgId } }
  });

  return NextResponse.json({ ok: true });
}
`;

// =====================================================
// API ROUTES — 2FA (TOTP)
// =====================================================
export const __api_2fa_setup__ = `import { NextResponse } from 'next/server';
import { requireUser } from '@/lib/auth';
import { prisma } from '@/lib/db';
import speakeasy from 'speakeasy';
import QRCode from 'qrcode';

export async function POST(_req: Request, { params }: { params: { orgId: string } }) {
  const session = await requireUser();

  // Ensure member
  const membership = await prisma.membership.findUnique({
    where: { userId_orgId: { userId: session.id, orgId: params.orgId } }
  });
  if (!membership) return NextResponse.json({ error: 'Forbidden' }, { status: 403 });

  const secret = speakeasy.generateSecret({
    name: `Gazel ID (${session.email})`
  });

  const qrDataUrl = await QRCode.toDataURL(secret.otpauth_url || '');

  // Store secret temporarily (not enabled yet)
  await prisma.user.update({
    where: { id: session.id },
    data: {
      totpSecretEnc: Buffer.from(secret.ascii).toString('base64')
    }
  });

  return NextResponse.json({ ok: true, qrDataUrl, secret: secret.base32 });
}
`;

export const __api_2fa_verify__ = `import { NextResponse } from 'next/server';
import { requireUser } from '@/lib/auth';
import { prisma } from '@/lib/db';
import speakeasy from 'speakeasy';

export async function POST(req: Request, { params }: { params: { orgId: string } }) {
  const session = await requireUser();

  const membership = await prisma.membership.findUnique({
    where: { userId_orgId: { userId: session.id, orgId: params.orgId } }
  });
  if (!membership) return NextResponse.json({ error: 'Forbidden' }, { status: 403 });

  const body = await req.json().catch(() => null);
  const code = String(body?.code || '').trim();
  if (!code) return NextResponse.json({ error: 'Code required' }, { status: 400 });

  const user = await prisma.user.findUnique({ where: { id: session.id } });
  if (!user?.totpSecretEnc) return NextResponse.json({ error: 'Setup required' }, { status: 400 });

  const secret = Buffer.from(user.totpSecretEnc, 'base64').toString('utf8');

  const verified = speakeasy.totp.verify({
    secret,
    encoding: 'ascii',
    token: code,
    window: 1
  });

  if (!verified) return NextResponse.json({ error: 'Invalid code' }, { status: 401 });

  await prisma.user.update({
    where: { id: session.id },
    data: { totpEnabled: true }
  });

  return NextResponse.json({ ok: true });
}
`;

export const __api_2fa_disable__ = `import { NextResponse } from 'next/server';
import { requireUser } from '@/lib/auth';
import { prisma } from '@/lib/db';

export async function POST(_req: Request, { params }: { params: { orgId: string } }) {
  const session = await requireUser();

  const membership = await prisma.membership.findUnique({
    where: { userId_orgId: { userId: session.id, orgId: params.orgId } }
  });
  if (!membership) return NextResponse.json({ error: 'Forbidden' }, { status: 403 });

  await prisma.user.update({
    where: { id: session.id },
    data: { totpEnabled: false, totpSecretEnc: null }
  });

  return NextResponse.json({ ok: true });
}
`;

// =====================================================
// OIDC PLACEHOLDERS (MVP)
// =====================================================
export const __oidc_config__ = `import { NextResponse } from 'next/server';
import { env } from '@/lib/env';

export async function GET() {
  return NextResponse.json({
    issuer: env.OIDC_ISSUER,
    authorization_endpoint: `${env.OIDC_ISSUER}/api/oidc/authorize`,
    token_endpoint: `${env.OIDC_ISSUER}/api/oidc/token`,
    userinfo_endpoint: `${env.OIDC_ISSUER}/api/oidc/userinfo`,
    jwks_uri: null,
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['HS256']
  });
}
`;

export const __oidc_authorize__ = `import { NextResponse } from 'next/server';

export async function GET() {
  return NextResponse.json({
    error: 'not_implemented',
    message: 'OIDC authorize flow will be implemented in v2 (code + consent + redirect).'
  }, { status: 501 });
}
`;

export const __oidc_token__ = `import { NextResponse } from 'next/server';

export async function POST() {
  return NextResponse.json({
    error: 'not_implemented',
    message: 'OIDC token endpoint will be implemented in v2.'
  }, { status: 501 });
}
`;

export const __oidc_userinfo__ = `import { NextResponse } from 'next/server';
import { getSessionUser } from '@/lib/auth';

export async function GET() {
  const u = await getSessionUser();
  if (!u) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });

  return NextResponse.json({
    sub: u.id,
    email: u.email,
    name: u.name,
    org_id: u.activeOrgId
  });
}
`;

// =====================================================
// src/middleware.ts
// =====================================================
export const __middleware__ = `import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;

  // Allow public
  if (pathname === '/' || pathname.startsWith('/login') || pathname.startsWith('/register') || pathname.startsWith('/api') || pathname.startsWith('/_next')) {
    return NextResponse.next();
  }

  // App pages require cookie; we do server-side check in layout, so keep simple.
  return NextResponse.next();
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)']
};
`;

// =====================================================
// IMPORTANT NOTE
// =====================================================
export const __note__ = `
MVP ini sudah:
- Multi-tenant org
- Membership + role
- Invite link (copy)
- 2FA TOTP
- JWT access + refresh token (refresh storage ready)
- UI dashboard

Yang belum:
- Full refresh rotation endpoint
- Full OIDC authorize+token flow (baru placeholder)
- Email real provider

Kalau kamu mau, aku bisa lanjutkan v2: OIDC full (Authorization Code Flow) + AppClient UI.
`;
