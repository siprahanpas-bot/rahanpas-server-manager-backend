<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->string('phone', 20)->nullable()->unique();
            $table->string('account_status', 40)->default('active');
        });

        Schema::create('account_activation_tokens', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();
            $table->string('purpose', 40);
            $table->string('token_hash', 64)->unique();
            $table->timestamp('expires_at');
            $table->timestamp('used_at')->nullable();
            $table->timestamps();
            $table->index(['user_id', 'purpose']);
        });

        Schema::create('groups', function (Blueprint $table) {
            $table->id();
            $table->string('name')->unique();
            $table->string('slug')->unique();
            $table->text('description')->nullable();
            $table->timestamps();
        });

        Schema::create('roles', function (Blueprint $table) {
            $table->id();
            $table->string('name')->unique();
            $table->string('slug')->unique();
            $table->text('description')->nullable();
            $table->timestamps();
        });

        Schema::create('permissions', function (Blueprint $table) {
            $table->id();
            $table->string('name')->unique();
            $table->string('slug')->unique();
            $table->text('description')->nullable();
            $table->timestamps();
        });

        Schema::create('group_user', function (Blueprint $table) {
            $table->foreignId('group_id')->constrained()->cascadeOnDelete();
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();
            $table->primary(['group_id', 'user_id']);
        });

        Schema::create('group_role', function (Blueprint $table) {
            $table->foreignId('group_id')->constrained()->cascadeOnDelete();
            $table->foreignId('role_id')->constrained()->cascadeOnDelete();
            $table->primary(['group_id', 'role_id']);
        });

        Schema::create('permission_role', function (Blueprint $table) {
            $table->foreignId('permission_id')->constrained()->cascadeOnDelete();
            $table->foreignId('role_id')->constrained()->cascadeOnDelete();
            $table->primary(['permission_id', 'role_id']);
        });

        $now = now();

        $permissions = [
            'server.view', 'server.create', 'server.update', 'server.delete', 'server.connect',
            'monitoring.view',
            'files.view', 'files.create', 'files.rename', 'files.delete', 'files.upload',
            'storage.view', 'storage.mount', 'storage.unmount', 'storage.format',
            'users.view', 'users.manage',
            'groups.manage', 'roles.manage', 'permissions.manage',
        ];

        foreach ([
            ['Registered User', 'registered-user', 'Akun terdaftar tanpa hak akses administratif.'],
            ['Pending Verification', 'pending-verification', 'Akun yang belum menyelesaikan aktivasi.'],
            ['Super Administrator', 'super-administrator', 'Akses penuh ke seluruh fitur.'],
        ] as [$name, $slug, $description]) {
            DB::table('groups')->insert([
                'name' => $name, 'slug' => $slug,
                'description' => $description,
                'created_at' => $now, 'updated_at' => $now,
            ]);
        }

        DB::table('roles')->insert([
            'name' => 'Super Administrator',
            'slug' => 'super-administrator',
            'description' => 'Seluruh permission aplikasi.',
            'created_at' => $now, 'updated_at' => $now,
        ]);

        foreach ($permissions as $permission) {
            DB::table('permissions')->insert([
                'name' => ucwords(str_replace('.', ' ', $permission)),
                'slug' => $permission,
                'created_at' => $now, 'updated_at' => $now,
            ]);
        }

        $adminGroup = DB::table('groups')->where('slug', 'super-administrator')->value('id');
        $adminRole = DB::table('roles')->where('slug', 'super-administrator')->value('id');

        DB::table('group_role')->insert([
            'group_id' => $adminGroup,
            'role_id' => $adminRole,
        ]);

        $permissionIds = DB::table('permissions')->pluck('id')->all();

        DB::table('permission_role')->insert(
            array_map(fn ($id) => [
                'permission_id' => $id,
                'role_id' => $adminRole,
            ], $permissionIds)
        );
    }

    public function down(): void
    {
        Schema::dropIfExists('permission_role');
        Schema::dropIfExists('group_role');
        Schema::dropIfExists('group_user');
        Schema::dropIfExists('permissions');
        Schema::dropIfExists('roles');
        Schema::dropIfExists('groups');
        Schema::dropIfExists('account_activation_tokens');

        Schema::table('users', function (Blueprint $table) {
            $table->dropUnique(['phone']);
            $table->dropColumn(['phone', 'account_status']);
        });
    }
};
