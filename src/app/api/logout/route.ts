import { NextRequest, NextResponse } from 'next/server';

import { accessSessionCookie } from '@/lib/access-session';

export const runtime = 'edge';

export async function POST(request: NextRequest) {
  const response = NextResponse.json({ ok: true });

  // 清除认证cookie
  response.cookies.set('auth', '', {
    path: '/',
    expires: new Date(0),
    sameSite: 'lax', // 改为 lax 以支持 PWA
    httpOnly: false, // PWA 需要客户端可访问
    secure: false, // 根据协议自动设置
  });

  const { name, ...options } = accessSessionCookie;
  response.cookies.set(name, '', {
    ...options,
    maxAge: 0,
    secure: request.nextUrl.protocol === 'https:',
  });

  return response;
}
