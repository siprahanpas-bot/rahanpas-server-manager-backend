<?php

return [
    'super_admin_email' => strtolower(trim((string) env('SUPER_ADMIN_EMAIL', ''))),

    'rdp_bridge' => [
        'secret' => (string) env('RDP_BRIDGE_SECRET', ''),
        'public_port' => (int) env('RDP_BRIDGE_PUBLIC_PORT', 13002),
    ],

    'onlyoffice' => [
        'public_port' => (int) env('ONLYOFFICE_PUBLIC_PORT', 13009),
        'api_base_url' => rtrim(
            (string) env('ONLYOFFICE_API_BASE_URL', 'http://rahanpas-backend-nginx/api'),
            '/'
        ),
        'internal_url' => rtrim(
            (string) env('ONLYOFFICE_INTERNAL_URL', 'http://rahanpas-onlyoffice'),
            '/'
        ),
    ],
];
