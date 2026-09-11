# API QA Report

Date: 2026-09-11

## Overview

This report summarizes the verified behavior of the FastAPI boilerplate after fixing the request body-size issue that caused the service to enter recovery mode.

Key validation targets:
- User login: talha / Talha@6295
- Admin login: admin / Admin@123
- Cookie-based login with Redis refresh tracking
- Token refresh flow
- Invalid-token rejection
- Oversized request rejection

## Executive Summary

- All critical auth flows passed on the fixed local instance
- Health endpoint returned 200 OK
- User and admin login succeeded with JWT issuance
- Cookie-based login set the expected session cookies
- Refresh token rotation succeeded
- Invalid tokens were rejected with 401
- Oversized body requests were blocked instead of crashing the middleware

## Verification Results

| Check | Outcome | Evidence |
|---|---|---|
| Health endpoint | Pass | HTTP 200 |
| User login | Pass | HTTP 200 with access + refresh tokens |
| Admin login | Pass | HTTP 200 with admin claims |
| Cookie login | Pass | CSO + refresh_token cookies set |
| Refresh flow | Pass | HTTP 200 and new token returned |
| Invalid token | Pass | HTTP 401 |
| Body-size guard | Pass | Request rejected before route logic |

## Status Graph

<svg viewBox="0 0 760 250" xmlns="http://www.w3.org/2000/svg" width="100%" height="250">
  <rect width="760" height="250" fill="#f8fafc"/>
  <text x="30" y="35" font-size="24" font-family="Arial, sans-serif" font-weight="700" fill="#0f172a">Authentication and Security QA</text>

  <g transform="translate(70,60)">
    <g>
      <rect x="0" y="60" width="60" height="90" fill="#22c55e" rx="6"/>
      <text x="30" y="170" text-anchor="middle" font-size="11" font-family="Arial, sans-serif" fill="#0f172a">Health</text>
    </g>
    <g>
      <rect x="90" y="40" width="60" height="110" fill="#22c55e" rx="6"/>
      <text x="120" y="170" text-anchor="middle" font-size="11" font-family="Arial, sans-serif" fill="#0f172a">User</text>
    </g>
    <g>
      <rect x="180" y="40" width="60" height="110" fill="#22c55e" rx="6"/>
      <text x="210" y="170" text-anchor="middle" font-size="11" font-family="Arial, sans-serif" fill="#0f172a">Admin</text>
    </g>
    <g>
      <rect x="270" y="35" width="60" height="115" fill="#22c55e" rx="6"/>
      <text x="300" y="170" text-anchor="middle" font-size="11" font-family="Arial, sans-serif" fill="#0f172a">Cookie</text>
    </g>
    <g>
      <rect x="360" y="48" width="60" height="102" fill="#22c55e" rx="6"/>
      <text x="390" y="170" text-anchor="middle" font-size="11" font-family="Arial, sans-serif" fill="#0f172a">Refresh</text>
    </g>
    <g>
      <rect x="450" y="28" width="60" height="122" fill="#22c55e" rx="6"/>
      <text x="480" y="170" text-anchor="middle" font-size="11" font-family="Arial, sans-serif" fill="#0f172a">Invalid</text>
    </g>
    <g>
      <rect x="540" y="20" width="60" height="130" fill="#22c55e" rx="6"/>
      <text x="570" y="170" text-anchor="middle" font-size="11" font-family="Arial, sans-serif" fill="#0f172a">Body</text>
    </g>

    <line x1="0" y1="150" x2="620" y2="150" stroke="#94a3b8" stroke-width="1.2"/>
    <line x1="0" y1="150" x2="0" y2="0" stroke="#94a3b8" stroke-width="1.2"/>
    <line x1="0" y1="0" x2="620" y2="0" stroke="#94a3b8" stroke-width="1.2"/>
    <line x1="620" y1="0" x2="620" y2="150" stroke="#94a3b8" stroke-width="1.2"/>
  </g>
</svg>

## Pass/Fail Distribution

<svg viewBox="0 0 480 260" xmlns="http://www.w3.org/2000/svg" width="100%" height="260">
  <rect width="480" height="260" fill="#f8fafc"/>
  <text x="30" y="36" font-size="24" font-family="Arial, sans-serif" font-weight="700" fill="#0f172a">Pass/Fail Split</text>

  <circle cx="170" cy="140" r="72" fill="#22c55e"/>
  <circle cx="170" cy="140" r="72" fill="none" stroke="#f8fafc" stroke-width="40" stroke-dasharray="260 260" stroke-dashoffset="0" transform="rotate(-90 170 140)"/>
  <circle cx="170" cy="140" r="72" fill="none" stroke="#ef4444" stroke-width="40" stroke-dasharray="0 500" stroke-dashoffset="0" transform="rotate(-90 170 140)"/>

  <text x="170" y="145" text-anchor="middle" font-size="25" font-family="Arial, sans-serif" font-weight="700" fill="#0f172a">7/7</text>

  <rect x="280" y="90" width="18" height="18" fill="#22c55e"/>
  <text x="310" y="106" font-size="18" font-family="Arial, sans-serif" fill="#0f172a">Passed: 7</text>

  <rect x="280" y="125" width="18" height="18" fill="#ef4444"/>
  <text x="310" y="141" font-size="18" font-family="Arial, sans-serif" fill="#0f172a">Failed: 0</text>
</svg>

## Root Cause and Fix

The issue was caused by a numeric mismatch in the request-body size check:
- `Content-Length` was read as an integer
- `MAX_BODY_SIZE` was being treated as a string-based value in some flows
- the comparison triggered a TypeError and moved the app into auto-kill recovery mode

The fix normalized both values to integer byte counts before comparison, and the middleware now enforces the configured body size safely.

## Notes

- Verified on a fixed local instance on 127.0.0.1:2027
- The earlier remote 503 behavior was caused by the stale auto-kill state created by the body-size bug
- The service is healthy after the fix and the login/security paths are working as expected
