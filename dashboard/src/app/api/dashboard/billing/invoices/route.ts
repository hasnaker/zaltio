import { NextRequest, NextResponse } from 'next/server';

export async function GET(request: NextRequest) {
  try {
    // Mock invoices - in production this would come from Stripe
    const invoices = [
      { id: 'inv_1', amount: 9900, status: 'paid' as const, date: '2026-02-01T00:00:00Z', pdfUrl: '#' },
      { id: 'inv_2', amount: 9900, status: 'paid' as const, date: '2026-01-01T00:00:00Z', pdfUrl: '#' },
      { id: 'inv_3', amount: 9900, status: 'paid' as const, date: '2025-12-01T00:00:00Z', pdfUrl: '#' },
    ];

    return NextResponse.json({ invoices });
  } catch (error) {
    return NextResponse.json({ error: 'Failed to fetch invoices' }, { status: 500 });
  }
}
