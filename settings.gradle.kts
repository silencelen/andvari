pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "andvari"

include(":core")
include(":server")
include(":app-android")
include(":app-desktop")
include(":tools:vector-gen")
include(":tools:recovery-cli")
include(":tools:backup-cli")
include(":tools:update-signer")
// The iOS UI tests' seeding tool. An image build copies only the modules it needs, so this one may be absent.
if (file("tools/uitest-seed").isDirectory) include(":tools:uitest-seed")
