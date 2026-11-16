<?php

namespace Tests\Feature;

use Tests\TestCase;

class ApiAuthenticationTest extends TestCase
{
    public function test_protected_api_routes_return_json_401_without_accept_header(): void
    {
        $endpoints = [
            '/api/me',
            '/api/servers',
            '/api/admin/users',
        ];

        foreach ($endpoints as $endpoint) {
            $response = $this->get($endpoint);

            $response
                ->assertUnauthorized()
                ->assertJson([
                    'message' => 'Unauthenticated.',
                ]);
        }
    }
}
