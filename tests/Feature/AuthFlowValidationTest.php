<?php

namespace Tests\Feature;

use Tests\TestCase;

class AuthFlowValidationTest extends TestCase
{
    public function test_login_requires_email_password_and_device_name(): void
    {
        $response = $this->postJson('/api/login', []);

        $response
            ->assertUnprocessable()
            ->assertJsonValidationErrors([
                'email',
                'password',
                'device_name',
            ]);
    }

    public function test_registration_requires_name_phone_and_email(): void
    {
        $response = $this->postJson('/api/register', []);

        $response
            ->assertUnprocessable()
            ->assertJsonValidationErrors([
                'name',
                'phone',
                'email',
            ]);
    }

    public function test_google_exchange_rejects_request_when_oauth_is_not_configured(): void
    {
        $this->assertSame('', (string) env('GOOGLE_CLIENT_ID', ''));
        $this->assertSame('', (string) env('GOOGLE_CLIENT_SECRET', ''));

        $response = $this->postJson('/api/auth/google/exchange', [
            'code' => 'test-authorization-code',
            'redirect_uri' => 'https://example.test/auth/callback',
        ]);

        $response
            ->assertUnprocessable()
            ->assertJson([
                'message' => 'Google OAuth belum dikonfigurasi (GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET kosong).',
            ]);
    }
}
